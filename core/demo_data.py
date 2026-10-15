"""
core/demo_data.py
=================
Generates ~150 realistic vulnerability findings across ~15 hosts.

Hosts span: Windows servers, Linux servers, workstations, and network devices.
CVE IDs, CVSS scores, and services are drawn from real-world 2022-2024 CVEs.
Dates are distributed over the past 6 months.
"""

from __future__ import annotations

import random
from datetime import date, timedelta
from typing import Any

from core.scoring import compute_risk_score, cvss_to_severity, sla_target_date, is_overdue

# ---------------------------------------------------------------------------
# Source data pools
# ---------------------------------------------------------------------------

HOSTS = [
    {"asset": "WIN-DC01",         "asset_type": "Server-Windows",  "asset_criticality": "High"},
    {"asset": "WIN-DC02",         "asset_type": "Server-Windows",  "asset_criticality": "High"},
    {"asset": "WIN-FILESVR01",    "asset_type": "Server-Windows",  "asset_criticality": "High"},
    {"asset": "WIN-APPSVR01",     "asset_type": "Server-Windows",  "asset_criticality": "Medium"},
    {"asset": "WIN-WKS-ADMIN01",  "asset_type": "Workstation",     "asset_criticality": "High"},
    {"asset": "WIN-WKS-USER15",   "asset_type": "Workstation",     "asset_criticality": "Low"},
    {"asset": "LNX-WEBSVR01",     "asset_type": "Server-Linux",    "asset_criticality": "High"},
    {"asset": "LNX-DBSVR01",      "asset_type": "Server-Linux",    "asset_criticality": "High"},
    {"asset": "LNX-DEVSVR01",     "asset_type": "Server-Linux",    "asset_criticality": "Medium"},
    {"asset": "LNX-BACKUP01",     "asset_type": "Server-Linux",    "asset_criticality": "Medium"},
    {"asset": "LNX-MONITOR01",    "asset_type": "Server-Linux",    "asset_criticality": "Low"},
    {"asset": "NET-CORE-SW01",    "asset_type": "Network",         "asset_criticality": "High"},
    {"asset": "NET-FW-EDGE01",    "asset_type": "Network",         "asset_criticality": "High"},
    {"asset": "NET-AP-FLOOR2",    "asset_type": "Network",         "asset_criticality": "Medium"},
    {"asset": "NET-SWITCH-DMZ",   "asset_type": "Network",         "asset_criticality": "Medium"},
]

# Real CVE data pool: (cve_id, cvss, description, service, port, nist_csf, iso_control)
CVE_POOL: list[tuple[str, float, str, str, int, str, str]] = [
    # Critical
    ("CVE-2021-44228", 10.0, "Apache Log4Shell RCE via JNDI injection",           "apache-log4j/2.14.1",  443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2021-26855", 9.8,  "Microsoft Exchange Server SSRF (ProxyLogon)",        "exchange/15.1.2375",   443,  "Identify,Protect,Respond", "A.8.8"),
    ("CVE-2022-26134", 9.8,  "Confluence OGNL injection RCE",                      "confluence/7.13.0",    8090, "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2023-23397", 9.8,  "Microsoft Outlook NTLM hash leak via calendar item", "outlook/16.0.15726",   443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2021-34527", 9.8,  "Windows Print Spooler RCE (PrintNightmare)",         "spoolsv/10.0.19041",   445,  "Identify,Protect,Respond", "A.8.8"),
    ("CVE-2022-30190", 9.8,  "Microsoft MSDT RCE (Follina)",                       "msdt/10.0.19041",      0,    "Identify,Respond",         "A.8.8"),
    ("CVE-2023-4966",  9.4,  "Citrix Bleed – NetScaler session token leak",        "netscaler/13.1-49.15", 443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2021-44832", 9.0,  "Apache Log4j2 RCE via JDBC Appender",               "apache-log4j/2.17.0",  8080, "Identify,Detect",          "A.8.8"),
    ("CVE-2023-20198", 10.0, "Cisco IOS XE Web UI privilege escalation",           "cisco-iosxe/17.9.1a",  443,  "Identify,Protect,Respond", "A.8.8"),
    ("CVE-2023-44487", 7.5,  "HTTP/2 Rapid Reset DoS (CVE-2023-44487)",            "nginx/1.24.0",         443,  "Protect,Detect",           "A.12.6"),
    # High
    ("CVE-2021-21985", 9.8,  "VMware vCenter Server RCE via vSAN Health Check",    "vcenter/7.0.0.10600",  443,  "Identify,Detect",          "A.8.8"),
    ("CVE-2021-40444", 8.8,  "Microsoft MSHTML RCE via Office documents",          "mshtml/11.0.19041",    0,    "Protect,Respond",          "A.8.8"),
    ("CVE-2022-1388",  9.8,  "F5 BIG-IP iControl REST auth bypass RCE",           "f5-bigip/16.1.2.2",    443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2022-22965", 9.8,  "Spring4Shell – Spring Framework RCE",               "spring-core/5.3.17",   8080, "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2022-0847",  7.8,  "Linux kernel Dirty Pipe local privilege escalation", "kernel/5.8.0",         0,    "Protect",                  "A.8.8"),
    ("CVE-2023-0386",  7.8,  "Linux kernel OverlayFS privilege escalation",        "kernel/6.1.0",         0,    "Protect",                  "A.8.8"),
    ("CVE-2021-3156",  7.8,  "sudo heap overflow – Baron Samedit",                 "sudo/1.9.5p1",         0,    "Protect",                  "A.9.4"),
    ("CVE-2022-21907", 9.8,  "Windows HTTP Protocol Stack RCE (worm potential)",   "http.sys/10.0.19041",  80,   "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2023-21716", 9.8,  "Microsoft Word RTF font table heap corruption",      "winword/16.0.16501",   0,    "Protect,Respond",          "A.8.8"),
    ("CVE-2021-42278", 8.8,  "Active Directory sAMAccountName spoofing (noPac)",   "kerberos/10.0.17763",  88,   "Identify,Protect",         "A.9.2"),
    # Medium
    ("CVE-2023-32784", 7.5,  "KeePass master password plaintext in memory dump",   "keepass/2.53",         0,    "Protect",                  "A.10.1"),
    ("CVE-2022-3602",  7.5,  "OpenSSL X.509 buffer overflow (punycode)",           "openssl/3.0.6",        443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2023-27350", 9.8,  "PaperCut NG auth bypass RCE",                        "papercut/22.0.5",      9191, "Identify,Detect",          "A.8.8"),
    ("CVE-2021-22986", 9.8,  "F5 BIG-IP iControl auth bypass",                     "f5-bigip/15.1.2",      443,  "Identify,Protect",         "A.9.4"),
    ("CVE-2022-27925", 7.2,  "Zimbra arbitrary file upload via mboximport",         "zimbra/8.8.15",        443,  "Protect,Detect",           "A.8.8"),
    ("CVE-2022-40684", 9.8,  "Fortinet FortiOS auth bypass",                        "fortios/7.2.1",        443,  "Identify,Protect",         "A.9.4"),
    ("CVE-2023-20273", 7.2,  "Cisco IOS XE command injection",                      "cisco-iosxe/17.9.2",   443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2023-2868",  9.8,  "Barracuda ESG command injection",                     "barracuda-esg/9.2.1",  25,   "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2022-47966", 9.8,  "ManageEngine multiple products RCE (SAML)",           "manageengine/14.0",    8443, "Identify,Detect",          "A.8.8"),
    ("CVE-2023-29357", 9.8,  "Microsoft SharePoint privilege escalation",           "sharepoint/16.0.15601",443,  "Identify,Protect",         "A.9.2"),
    # Low / Medium
    ("CVE-2022-1096",  8.8,  "Google Chrome V8 type confusion",                    "chrome/99.0.4844.84",  0,    "Protect",                  "A.8.8"),
    ("CVE-2023-36884", 8.8,  "Microsoft Office/Windows HTML RCE",                  "office/16.0.16501",    0,    "Protect,Respond",          "A.8.8"),
    ("CVE-2022-24521", 7.8,  "Windows CLFS driver privilege escalation",           "clfs/10.0.19041",      0,    "Protect",                  "A.8.8"),
    ("CVE-2021-36942", 7.5,  "Windows LSA Spoofing (PetitPotam)",                  "lsass/10.0.19041",     445,  "Identify,Protect",         "A.9.4"),
    ("CVE-2022-26923", 8.8,  "Active Directory Certificate Services LPE",          "adcs/10.0.17763",      0,    "Identify,Protect",         "A.9.2"),
    ("CVE-2023-21554", 9.8,  "Windows MSMQ RCE (QueueJumper)",                    "msmq/10.0.19041",      1801, "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2023-28252", 7.8,  "Windows CLFS zero-day LPE",                          "clfs/10.0.19044",      0,    "Protect",                  "A.8.8"),
    ("CVE-2022-34718", 9.8,  "Windows TCP/IP RCE (IPv6)",                          "tcpip.sys/10.0.19041", 0,    "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2023-36745", 8.8,  "Microsoft Exchange Server RCE",                      "exchange/15.2.1118",   443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2021-27085", 8.8,  "Internet Explorer scripting engine RCE",             "jscript9/11.0.19041",  0,    "Protect",                  "A.8.8"),
    # Additional to reach ~150
    ("CVE-2022-21999", 7.8,  "Windows Print Spooler LPE",                          "spoolsv/10.0.19041",   0,    "Protect",                  "A.8.8"),
    ("CVE-2021-26857", 7.8,  "Microsoft Exchange insecure deserialization LPE",    "exchange/15.1.2375",   443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2023-35311", 8.8,  "Microsoft Outlook security bypass",                  "outlook/16.0.16501",   443,  "Protect,Respond",          "A.8.8"),
    ("CVE-2022-24686", 7.8,  "HashiCorp Nomad privilege escalation",               "nomad/1.1.9",          4646, "Protect",                  "A.9.4"),
    ("CVE-2023-34048", 9.8,  "VMware vCenter Server out-of-bounds write RCE",      "vcenter/8.0.1.00100",  443,  "Identify,Detect",          "A.8.8"),
    ("CVE-2024-1709",  10.0, "ConnectWise ScreenConnect auth bypass",              "screenconnect/23.9.7", 8040, "Identify,Detect,Respond",  "A.9.4"),
    ("CVE-2024-3400",  10.0, "Palo Alto PAN-OS GlobalProtect RCE",                 "panos/11.1.0",         443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2024-21762", 9.8,  "Fortinet FortiOS SSL VPN out-of-bounds write RCE",   "fortios/7.4.2",        443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2024-21887", 9.1,  "Ivanti Connect Secure command injection",            "ivanti-ics/22.3.4",    443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2024-27198", 9.8,  "JetBrains TeamCity auth bypass",                     "teamcity/2023.11.3",   8111, "Identify,Protect",         "A.9.4"),
]

OWNERS = [
    "alice.johnson@corp.local",
    "bob.smith@corp.local",
    "carol.white@corp.local",
    "dave.chen@corp.local",
    "SecOps-Team",
    "NetOps-Team",
    "WinAdmin-Team",
    "LinuxAdmin-Team",
]

STATUSES = ["Open", "Open", "Open", "In Progress", "In Progress", "Mitigated", "Accepted"]


def _random_date_within(days: int) -> date:
    """Return a random date within the past `days` days."""
    delta = random.randint(0, days)
    return date.today() - timedelta(days=delta)


def generate_demo_findings(target_count: int = 150, seed: int = 42) -> list[dict[str, Any]]:
    """
    Generate realistic vulnerability findings for demonstration.

    Parameters
    ----------
    target_count:
        Approximate number of findings to generate.
    seed:
        Random seed for reproducibility.
    """
    random.seed(seed)
    findings: list[dict[str, Any]] = []

    while len(findings) < target_count:
        host = random.choice(HOSTS)
        cve_data = random.choice(CVE_POOL)
        cve_id, cvss, description, service, port, nist_csf, iso_control = cve_data

        # Slightly vary CVSS ±0.2 to avoid perfectly identical scores
        cvss_jitter = round(max(0.0, min(10.0, cvss + random.uniform(-0.2, 0.2))), 1)

        severity = cvss_to_severity(cvss_jitter)
        risk_score = compute_risk_score(cvss_jitter, host["asset_criticality"])

        # Weight older findings toward Open, recent ones toward In Progress/Mitigated
        date_found = _random_date_within(180)
        age_days = (date.today() - date_found).days
        if age_days > 120:
            status_pool = ["Open", "In Progress", "Mitigated", "Accepted"]
            weights = [0.25, 0.25, 0.35, 0.15]
        elif age_days > 60:
            status_pool = ["Open", "In Progress", "Mitigated", "Accepted"]
            weights = [0.40, 0.35, 0.20, 0.05]
        else:
            status_pool = ["Open", "In Progress", "Mitigated", "Accepted"]
            weights = [0.60, 0.30, 0.08, 0.02]

        status = random.choices(status_pool, weights=weights, k=1)[0]

        target = sla_target_date(severity, date_found)
        overdue = int(is_overdue(severity, date_found, status))
        owner = random.choice(OWNERS)

        findings.append(
            {
                "asset": host["asset"],
                "asset_type": host["asset_type"],
                "asset_criticality": host["asset_criticality"],
                "vulnerability": description,
                "cve": cve_id,
                "cvss": cvss_jitter,
                "severity": severity,
                "risk_score": risk_score,
                "service": service,
                "port": port if port else None,
                "owner": owner,
                "status": status,
                "date_found": date_found.isoformat(),
                "target_date": target.isoformat(),
                "overdue": overdue,
                "notes": "",
                "nist_csf": nist_csf,
                "iso_control": iso_control,
            }
        )

    return findings
