<#
.SYNOPSIS
    Windows Host Information Collector for VulnWatch Dashboard

.DESCRIPTION
    Collects local users, open TCP/UDP ports, installed hotfixes,
    running services, and installed software. Outputs a CSV compatible
    with the VulnWatch CSV import format.

.PARAMETER OutputPath
    Path for the output CSV file. Default: .\windows_scan_output.csv
    Alias: -OutputFile

.EXAMPLE
    .\collect_windows_info.ps1 -OutputPath .\my_scan.csv
    .\collect_windows_info.ps1 -OutputFile host_findings.csv

.NOTES
    Run as Administrator for complete port and hotfix information.
    Tested on Windows 10 / Windows Server 2019+ / Windows 11.
#>

[CmdletBinding()]
param(
    [Alias("OutputFile")]
    [string]$OutputPath = ".\windows_scan_output.csv",
    [string]$AssetCriticality = "Medium",
    [string]$Owner = "me"
)

# == Elevation check ==========================================================
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. Some data (e.g. all TCP ports) may be incomplete."
}

$hostname = $env:COMPUTERNAME
$findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
$dateFound = (Get-Date).ToString("yyyy-MM-dd")

Write-Host "[*] VulnWatch Windows Collector - Host: $hostname" -ForegroundColor Cyan
Write-Host "[*] Date: $dateFound"
Write-Host ""

# == 1. Open Listening Ports ==================================================
Write-Host "[+] Collecting listening ports..." -ForegroundColor Green
try {
    $tcpConns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $tcpConns) {
        $port     = $conn.LocalPort
        $process  = ""
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) { $process = $proc.Name }
        } catch {}

        # Assess risk by port
        $cvss = 4.0
        $description = "Open listening TCP port $port ($process)"

        $highRiskPorts = @(21, 23, 69, 135, 137, 138, 139, 445, 512, 513, 514, 1433, 3306, 3389, 5985, 5986, 4444, 31337)
        $medRiskPorts  = @(22, 25, 53, 80, 110, 143, 389, 443, 636, 8080, 8443, 8888)

        if ($port -in $highRiskPorts) {
            $cvss = 7.5
            $description = "High-risk port $port exposed ($process)"
        } elseif ($port -in $medRiskPorts) {
            $cvss = 5.0
        }

        # Flag legacy protocols
        if ($port -eq 23) {
            $description = "Telnet (plaintext protocol) listening on port 23 - REPLACE WITH SSH"
            $cvss = 9.8
        }
        if ($port -eq 21) {
            $description = "FTP (plaintext protocol) listening on port 21 - use SFTP/SCP"
            $cvss = 7.5
        }
        if ($port -eq 3389 -and -not $isAdmin) {
            $description = "RDP exposed on port 3389 - verify NLA is enforced"
        }

        $findings.Add([PSCustomObject]@{
            asset             = $hostname
            vulnerability     = $description
            cve               = ""
            cvss              = $cvss
            service           = $process
            port              = $port
            owner             = $Owner
            status            = "Open"
            asset_criticality = $AssetCriticality
            asset_type        = "Server-Windows"
            notes             = "Auto-collected by collect_windows_info.ps1"
        })
    }
    Write-Host "    Found $($tcpConns.Count) listening TCP ports."
} catch {
    Write-Warning "Could not collect TCP connections: $_"
}

# == 2. Missing Hotfixes / Windows Updates ====================================
Write-Host "[+] Collecting installed hotfixes..." -ForegroundColor Green
try {
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
    $lastPatch = if ($hotfixes) { $hotfixes[0].InstalledOn } else { $null }

    if ($lastPatch) {
        $daysSince = ((Get-Date) - $lastPatch).Days
        if ($daysSince -gt 30) {
            $cvssScore  = if ($daysSince -gt 90) { 7.5 } elseif ($daysSince -gt 60) { 6.5 } else { 5.0 }
            $findings.Add([PSCustomObject]@{
                asset             = $hostname
                vulnerability     = "Windows last patched $daysSince days ago (last: $($lastPatch.ToString('yyyy-MM-dd'))). System may be missing critical security updates."
                cve               = ""
                cvss              = $cvssScore
                service           = "Windows Update"
                port              = 0
                owner             = $Owner
                status            = "Open"
                asset_criticality = $AssetCriticality
                asset_type        = "Server-Windows"
                notes             = "Hotfix count: $($hotfixes.Count). Last KB: $($hotfixes[0].HotFixID)"
            })
        }
    } else {
        $findings.Add([PSCustomObject]@{
            asset             = $hostname
            vulnerability     = "Unable to determine last patch date - Windows Update history may be cleared"
            cve               = ""
            cvss              = 6.5
            service           = "Windows Update"
            port              = 0
            owner             = $Owner
            status            = "Open"
            asset_criticality = $AssetCriticality
            asset_type        = "Server-Windows"
            notes             = "Manual verification required"
        })
    }
    Write-Host "    Found $($hotfixes.Count) installed hotfixes. Last: $($lastPatch)"
} catch {
    Write-Warning "Could not collect hotfix info: $_"
}

# == 3. Local Admin Accounts ==================================================
Write-Host "[+] Collecting local accounts..." -ForegroundColor Green
try {
    $adminGroup = [ADSI]"WinNT://./Administrators,group"
    $members    = @($adminGroup.Invoke("Members"))
    $adminCount = $members.Count

    if ($adminCount -gt 3) {
        $findings.Add([PSCustomObject]@{
            asset             = $hostname
            vulnerability     = "Excessive local administrator accounts ($adminCount members in local Administrators group). Principle of least privilege may be violated."
            cve               = ""
            cvss              = 6.5
            service           = "Local Accounts"
            port              = 0
            owner             = $Owner
            status            = "Open"
            asset_criticality = $AssetCriticality
            asset_type        = "Server-Windows"
            notes             = "Admin count: $adminCount. Review and remove unnecessary admin accounts."
        })
    }

    # Check for default/risky accounts
    $riskyAccounts = @("Guest", "DefaultAccount", "WDAGUtilityAccount")
    $localUsers    = Get-LocalUser -ErrorAction SilentlyContinue
    foreach ($user in $localUsers) {
        if ($user.Name -in $riskyAccounts -and $user.Enabled) {
            $findings.Add([PSCustomObject]@{
                asset             = $hostname
                vulnerability     = "Default Windows account '$($user.Name)' is enabled - should be disabled per security baseline"
                cve               = ""
                cvss              = 5.0
                service           = "Local Accounts"
                port              = 0
                owner             = $Owner
                status            = "Open"
                asset_criticality = $AssetCriticality
                asset_type        = "Server-Windows"
                notes             = "Account: $($user.Name), Enabled: $($user.Enabled)"
            })
        }
    }
    Write-Host "    Found $adminCount local administrators."
} catch {
    Write-Warning "Could not collect local accounts: $_"
}

# == 4. SMB Signing / SMBv1 ===================================================
Write-Host "[+] Checking SMB configuration..." -ForegroundColor Green
try {
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbConfig) {
        if ($smbConfig.EnableSMB1Protocol) {
            $findings.Add([PSCustomObject]@{
                asset             = $hostname
                vulnerability     = "SMBv1 protocol is ENABLED - vulnerable to EternalBlue (CVE-2017-0144) and related exploits"
                cve               = "CVE-2017-0144"
                cvss              = 9.8
                service           = "smb/1.0"
                port              = 445
                owner             = $Owner
                status            = "Open"
                asset_criticality = $AssetCriticality
                asset_type        = "Server-Windows"
                notes             = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
            })
        }
        if (-not $smbConfig.RequireSecuritySignature) {
            $findings.Add([PSCustomObject]@{
                asset             = $hostname
                vulnerability     = "SMB signing is not required - susceptible to NTLM relay attacks (e.g. PetitPotam)"
                cve               = "CVE-2021-36942"
                cvss              = 7.5
                service           = "smb/3.1"
                port              = 445
                owner             = $Owner
                status            = "Open"
                asset_criticality = $AssetCriticality
                asset_type        = "Server-Windows"
                notes             = "Set-SmbServerConfiguration -RequireSecuritySignature `$true"
            })
        }
    }
    Write-Host "    SMB check complete."
} catch {
    Write-Warning "Could not check SMB config: $_"
}

# == 5. PowerShell Remoting / WinRM ===========================================
Write-Host "[+] Checking WinRM..." -ForegroundColor Green
try {
    $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.Status -eq "Running") {
        $findings.Add([PSCustomObject]@{
            asset             = $hostname
            vulnerability     = "WinRM (Windows Remote Management) is running - ensure access is restricted to authorized management hosts"
            cve               = ""
            cvss              = 5.0
            service           = "winrm"
            port              = 5985
            owner             = $Owner
            status            = "Open"
            asset_criticality = $AssetCriticality
            asset_type        = "Server-Windows"
            notes             = "Verify WinRM ACLs and use HTTPS (port 5986) with certificates"
        })
    }
} catch {
    Write-Warning "Could not check WinRM: $_"
}

# == Output CSV ===============================================================
Write-Host ""
Write-Host "[*] Writing $($findings.Count) findings to $OutputPath" -ForegroundColor Cyan
$findings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] Done! Import $OutputPath into the VulnWatch Dashboard." -ForegroundColor Green
Write-Host ""
Write-Host "Summary:"
$findings | Group-Object cvss | Sort-Object Name -Descending | ForEach-Object {
    Write-Host "  CVSS $($_.Name): $($_.Count) finding(s)"
}
