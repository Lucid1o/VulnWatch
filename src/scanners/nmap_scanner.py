"""
src/scanners/nmap_scanner.py
============================
Live network vulnerability and port scanner using Nmap with Vulners NSE integration.

Implements BaseScanner. Runs via subprocess with strict argument lists (never shell=True)
and enforces private IP validation before any execution.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import date
from typing import Any

from core.scoring import compute_risk_score, cvss_to_severity, sla_target_date, is_overdue
from src.scanners.base import BaseScanner, Finding
from src.scanners.validator import validate_scan_target

logger = logging.getLogger(__name__)

# Small rules table of preset risky services and fix advice when no CVE is present
RISKY_SERVICES_RULES: dict[int, dict[str, Any]] = {
    21: {
        "service": "ftp",
        "name": "FTP exposed (plaintext protocol)",
        "cvss": 7.5,
        "severity": "High",
        "advice": "Disable unencrypted FTP and migrate to SFTP (SSH File Transfer Protocol) or FTPS with TLS.",
        "nist_csf": "Protect",
        "iso_control": "A.8.8",
    },
    23: {
        "service": "telnet",
        "name": "Telnet open on port 23 (unencrypted remote access)",
        "cvss": 9.8,
        "severity": "Critical",
        "advice": "Telnet transmits credentials in cleartext. Immediately disable Telnet and replace with SSH.",
        "nist_csf": "Protect",
        "iso_control": "A.8.8",
    },
    445: {
        "service": "microsoft-ds",
        "name": "SMB file sharing exposed over network",
        "cvss": 7.5,
        "severity": "High",
        "advice": "Ensure SMBv1 is disabled, enable SMB message signing, and restrict port 445 via firewall.",
        "nist_csf": "Protect",
        "iso_control": "A.8.8",
    },
    3389: {
        "service": "ms-wbt-server",
        "name": "Remote Desktop Protocol (RDP) exposed",
        "cvss": 7.5,
        "severity": "High",
        "advice": "Restrict RDP access behind VPN/bastion host, require MFA, and enforce Network Level Authentication (NLA).",
        "nist_csf": "Protect",
        "iso_control": "A.9.4",
    },
    3306: {
        "service": "mysql",
        "name": "MySQL database port exposed directly to network",
        "cvss": 7.5,
        "severity": "High",
        "advice": "Bind database service to localhost/internal subnet only and restrict remote access via firewall.",
        "nist_csf": "Protect",
        "iso_control": "A.9.4",
    },
    5432: {
        "service": "postgresql",
        "name": "PostgreSQL database port exposed directly to network",
        "cvss": 7.5,
        "severity": "High",
        "advice": "Configure pg_hba.conf to deny untrusted connections and bind listener to private internal IP.",
        "nist_csf": "Protect",
        "iso_control": "A.9.4",
    },
    6379: {
        "service": "redis",
        "name": "Redis in-memory database exposed without isolation",
        "cvss": 9.0,
        "severity": "Critical",
        "advice": "Redis is designed for trusted environments; bind to 127.0.0.1, set strong requirepass, and disable dangerous commands.",
        "nist_csf": "Protect",
        "iso_control": "A.9.4",
    },
    27017: {
        "service": "mongodb",
        "name": "MongoDB database exposed to network",
        "cvss": 7.5,
        "severity": "High",
        "advice": "Enable authentication (auth=true), bind to localhost, and firewall port 27017.",
        "nist_csf": "Protect",
        "iso_control": "A.9.4",
    },
}


class NmapScanner(BaseScanner):
    """Live network vulnerability scanner leveraging Nmap and Vulners NSE script."""

    @property
    def name(self) -> str:
        return "Nmap Vulners Scanner"

    @classmethod
    def _get_nmap_env(cls) -> dict[str, str]:
        """Construct process environment with Nmap, Npcap, and C++ runtime DLL directories."""
        env = os.environ.copy()
        extra_dirs = [
            r"C:\Program Files (x86)\Nmap",
            r"C:\Program Files\Nmap",
            r"C:\Windows\SysWOW64\Npcap",
            r"C:\Windows\System32\Npcap",
            r"C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\Office16",
            r"C:\Program Files\Microsoft Office\root\vfs\ProgramFilesX86\Microsoft Office\Office16",
        ]
        valid_dirs = [d for d in extra_dirs if os.path.isdir(d)]
        if valid_dirs:
            prefix = os.pathsep.join(valid_dirs)
            env["PATH"] = f"{prefix}{os.pathsep}{env.get('PATH', '')}"
            # Also update current process os.environ so child subprocesses inherit it
            os.environ["PATH"] = env["PATH"]
        return env

    @classmethod
    def _find_nmap_binary(cls) -> str | None:
        """Locate the Nmap executable via PATH or standard installation directories."""
        cls._get_nmap_env()

        # 1. Standard PATH check
        path = shutil.which("nmap")
        if path:
            return path

        # 2. Common Windows paths
        win_candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe"),
        ]
        # 3. Common Unix/macOS paths
        unix_candidates = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/homebrew/bin/nmap",
        ]
        for candidate in win_candidates + unix_candidates:
            if os.path.isfile(candidate):
                return candidate

        return None

    def is_available(self) -> tuple[bool, str]:
        """Verify Nmap binary is present and can execute successfully."""
        nmap_path = self._find_nmap_binary()
        if not nmap_path:
            return (
                False,
                "Nmap is not installed or not in system PATH.\n"
                "To install Nmap:\n"
                " - Windows: run 'winget install Insecure.Nmap' or download from https://nmap.org/download.html\n"
                " - Ubuntu/Debian: run 'sudo apt install nmap'\n"
                " - macOS: run 'brew install nmap'",
            )

        # Smoke-test execution with resolved DLL paths
        try:
            res = subprocess.run(
                [nmap_path, "--version"],
                env=self._get_nmap_env(),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                first_line = res.stdout.strip().splitlines()[0] if res.stdout else "Nmap ready"
                return True, f"Nmap ready: {first_line} ({nmap_path})"
        except Exception:
            pass

        return True, f"Nmap found at: {nmap_path}"

    def scan(
        self,
        target: str,
        asset_criticality: str = "Medium",
        owner: str = "Unassigned",
        asset_type: str = "Host",
        timeout_seconds: int = 300,
    ) -> list[Finding]:
        """
        Execute Nmap scan against the validated target IP.

        Tries: `nmap -sV --script vulners -oX <tempfile> <target>`
        Fallback: If vulners script is unavailable, falls back to plain `nmap -sV`
        and records findings as 'service exposure'.
        """
        is_valid, err_msg, _ = validate_scan_target(target)
        if not is_valid:
            raise ValueError(f"Target validation failed: {err_msg}")

        nmap_bin = self._find_nmap_binary()
        if not nmap_bin:
            available, msg = self.is_available()
            raise RuntimeError(msg)

        nmap_env = self._get_nmap_env()

        # Temporary output file
        temp_fd, temp_path = tempfile.mkstemp(suffix=".xml", prefix="vulnwatch_nmap_")
        os.close(temp_fd)

        try:
            # 1. Primary command: -Pn -sV --script vulners
            cmd = [
                nmap_bin,
                "-Pn",
                "-sV",
                "--top-ports",
                "100",
                "--script",
                "vulners",
                "--script-timeout",
                "20s",
                "-oX",
                temp_path,
                target,
            ]
            logger.info("Running Nmap vulners scan: %s", " ".join(cmd))

            try:
                proc = subprocess.run(
                    cmd,
                    env=nmap_env,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                proc = subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr=f"Scan timed out after {timeout_seconds}s")

            # Check if XML was generated and is valid
            xml_valid = False
            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                try:
                    ET.parse(temp_path)
                    xml_valid = True
                except ET.ParseError:
                    xml_valid = False

            if not xml_valid:
                logger.warning(
                    "Nmap vulners scan did not produce valid XML; falling back to plain -sV scan."
                )
                cmd_fallback = [nmap_bin, "-Pn", "-sV", "--top-ports", "100", "-oX", temp_path, target]
                try:
                    proc_fallback = subprocess.run(
                        cmd_fallback,
                        env=nmap_env,
                        capture_output=True,
                        text=True,
                        timeout=timeout_seconds,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    proc_fallback = subprocess.CompletedProcess(cmd_fallback, returncode=-1, stdout="", stderr=f"Fallback scan timed out after {timeout_seconds}s")

                if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
                    error_detail = (proc_fallback.stderr or proc_fallback.stdout or proc.stderr or proc.stdout or "").strip()
                    raise RuntimeError(
                        f"Nmap scan failed: {error_detail or 'Host unreachable or no response. Ensure target IP is up and accessible.'}"
                    )

            with open(temp_path, "rb") as f:
                xml_bytes = f.read()

            findings = self.parse_nmap_xml(
                xml_bytes,
                default_target=target,
                asset_criticality=asset_criticality,
                owner=owner,
                asset_type=asset_type,
            )
            return findings

        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    @classmethod
    def parse_nmap_xml(
        cls,
        xml_bytes: bytes,
        default_target: str = "127.0.0.1",
        asset_criticality: str = "Medium",
        owner: str = "Unassigned",
        asset_type: str = "Host",
    ) -> list[Finding]:
        """
        Parse Nmap XML output (supporting both standard service banners and vulners CVE output).
        """
        findings: list[Finding] = []
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid Nmap XML output: {exc}") from exc

        today = date.today()

        for host_el in root.findall("host"):
            # Determine address
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            ip = addr_el.get("addr", default_target) if addr_el is not None else default_target

            # Determine hostname if present
            hostname = ip
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                hn_el = hostnames_el.find("hostname")
                if hn_el is not None and hn_el.get("name"):
                    hn_name = hn_el.get("name")
                    hostname = default_target if hn_name == "localhost" else hn_name

            # Determine OS / asset_type heuristic if caller did not provide a specific one
            detected_asset_type = asset_type
            if detected_asset_type in ("Host", "", None):
                os_match = host_el.find(".//osmatch")
                if os_match is not None and os_match.get("name"):
                    os_name = os_match.get("name", "").lower()
                    if "windows" in os_name:
                        detected_asset_type = "Laptop" if "workstation" in os_name or "10" in os_name or "11" in os_name else "Server-Windows"
                    elif "linux" in os_name:
                        detected_asset_type = "Home Server" if "server" in os_name else "Server-Linux"

            ports_el = host_el.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                try:
                    port_num = int(port_el.get("portid", 0))
                except ValueError:
                    port_num = 0

                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                service_full = f"{service_name} {product} {version}".strip()

                # Look for vulners script output
                vulners_cves: list[dict[str, Any]] = []
                for script_el in port_el.findall(".//script"):
                    if script_el.get("id") == "vulners":
                        vulners_cves.extend(cls._extract_vulners_cves(script_el))

                if vulners_cves:
                    # Record a finding for each detected CVE
                    for item in vulners_cves:
                        cve_id = item["cve"]
                        cvss_val = item["cvss"]
                        severity = cvss_to_severity(cvss_val)
                        risk = compute_risk_score(cvss_val, asset_criticality)
                        target_dt = sla_target_date(severity, today)
                        desc = f"{service_full or service_name}: {cve_id} detected via Nmap vulners"

                        findings.append(
                            Finding(
                                asset=hostname,
                                vulnerability=desc,
                                cve=cve_id,
                                cvss=cvss_val,
                                severity=severity,
                                risk_score=risk,
                                service=service_full or service_name,
                                port=port_num,
                                asset_type=detected_asset_type,
                                asset_criticality=asset_criticality,
                                owner=owner,
                                status="Open",
                                date_found=today.isoformat(),
                                target_date=target_dt.isoformat(),
                                overdue=0,
                                notes="Discovered by live Nmap vulners scan",
                                nist_csf="Identify,Detect",
                                iso_control="A.8.8",
                                source="nmap-live",
                            )
                        )
                else:
                    # No CVE from vulners -> Check risky services rules table
                    if port_num in RISKY_SERVICES_RULES:
                        rule = RISKY_SERVICES_RULES[port_num]
                        cvss_val = rule["cvss"]
                        severity = rule["severity"]
                        risk = compute_risk_score(cvss_val, asset_criticality)
                        target_dt = sla_target_date(severity, today)
                        desc = f"{rule['name']} ({service_full})" if service_full else rule["name"]

                        findings.append(
                            Finding(
                                asset=hostname,
                                vulnerability=desc,
                                cve="",
                                cvss=cvss_val,
                                severity=severity,
                                risk_score=risk,
                                service=service_full or rule["service"],
                                port=port_num,
                                asset_type=detected_asset_type,
                                asset_criticality=asset_criticality,
                                owner=owner,
                                status="Open",
                                date_found=today.isoformat(),
                                target_date=target_dt.isoformat(),
                                overdue=0,
                                notes=rule["advice"],
                                nist_csf=rule["nist_csf"],
                                iso_control=rule["iso_control"],
                                source="nmap-live",
                            )
                        )
                    else:
                        # Fallback service exposure
                        cvss_val = 4.0
                        severity = "Medium"
                        risk = compute_risk_score(cvss_val, asset_criticality)
                        target_dt = sla_target_date(severity, today)
                        desc = f"Service exposure: {service_full or service_name} listening on port {port_num}"

                        findings.append(
                            Finding(
                                asset=hostname,
                                vulnerability=desc,
                                cve="",
                                cvss=cvss_val,
                                severity=severity,
                                risk_score=risk,
                                service=service_full or service_name,
                                port=port_num,
                                asset_type=detected_asset_type,
                                asset_criticality=asset_criticality,
                                owner=owner,
                                status="Open",
                                date_found=today.isoformat(),
                                target_date=target_dt.isoformat(),
                                overdue=0,
                                notes="Verify necessity of exposed network service and apply firewall segmentation.",
                                nist_csf="Identify,Protect",
                                iso_control="A.8.8",
                                source="nmap-live",
                            )
                        )

        return findings

    @classmethod
    def _extract_vulners_cves(cls, script_el: ET.Element) -> list[dict[str, Any]]:
        """Extract CVE IDs and CVSS scores from Nmap vulners script XML element."""
        cves: list[dict[str, Any]] = []
        seen: set[str] = set()

        # 1. Parse structured XML table elements
        for elem in script_el.findall(".//elem[@key='id']"):
            cve_id = (elem.text or "").strip()
            if cve_id.startswith("CVE-") and cve_id not in seen:
                # Find matching CVSS in sibling or parent
                parent = elem.find("..")
                cvss_val = 5.0
                if parent is not None:
                    cvss_elem = parent.find(".//elem[@key='cvss']")
                    if cvss_elem is not None and cvss_elem.text:
                        try:
                            cvss_val = float(cvss_elem.text)
                        except ValueError:
                            cvss_val = 5.0
                seen.add(cve_id)
                cves.append({"cve": cve_id, "cvss": cvss_val})

        # 2. Text/regex fallback on output attribute if XML tables weren't present
        output_text = script_el.get("output", "")
        if output_text:
            matches = re.findall(r"(CVE-\d{4}-\d{4,7})\s+(\d+\.?\d*)", output_text)
            for cve_id, cvss_str in matches:
                if cve_id not in seen:
                    try:
                        cvss_val = float(cvss_str)
                    except ValueError:
                        cvss_val = 5.0
                    seen.add(cve_id)
                    cves.append({"cve": cve_id, "cvss": cvss_val})

        return cves
