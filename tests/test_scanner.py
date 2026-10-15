"""
tests/test_scanner.py
=====================
Comprehensive tests for Nmap live scanning, IP validation,
Vulners parser, risky services rules, and re-scan diff engine.
"""

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path
import pytest

from core.database import init_db, load_findings, get_scan_logs
from src.scanners.validator import validate_scan_target
from src.scanners.nmap_scanner import NmapScanner
from src.scanners.rescan import reconcile_scan_results
from src.scanners.base import Finding


# ---------------------------------------------------------------------------
# 1. Target Validation Tests
# ---------------------------------------------------------------------------

class TestTargetValidator:
    """Verifies target validation and legal/safety boundaries."""

    def test_valid_private_ips_accepted(self):
        valid_targets = [
            "10.0.0.1",
            "10.254.254.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "192.168.100.55",
            "127.0.0.1",
            "127.0.0.5",
        ]
        for ip in valid_targets:
            is_valid, err, _ = validate_scan_target(ip)
            assert is_valid, f"Expected {ip} to be valid, got error: {err}"

    def test_public_ips_rejected_for_safety(self):
        public_targets = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "142.250.190.46",
            "198.51.100.1",
        ]
        for ip in public_targets:
            is_valid, err, _ = validate_scan_target(ip)
            assert not is_valid
            assert "Authorization & Safety Restriction" in err or "not a private IP" in err

    def test_injection_attempts_rejected(self):
        attacks = [
            "192.168.1.1; rm -rf /",
            "192.168.1.1 && whoami",
            "192.168.1.1 | cat /etc/passwd",
            "192.168.1.1 `whoami`",
            "$(whoami)",
            "192.168.1.1 > out.txt",
            "192.168.1.1\nwhoami",
        ]
        for attack in attacks:
            is_valid, err, _ = validate_scan_target(attack)
            assert not is_valid
            assert "forbidden" in err.lower() or "invalid" in err.lower()

    def test_flags_rejected(self):
        flags = ["-sV", "--script", "-p 80", "-oN scan.txt", "-T4"]
        for flag in flags:
            is_valid, err, _ = validate_scan_target(flag)
            assert not is_valid
            assert "flag" in err.lower() or "not permitted" in err.lower()

    def test_malformed_and_empty_inputs(self):
        malformed = ["", "   ", "not_an_ip", "192.168.1.999", "192.168.1", "0.0.0.0"]
        for item in malformed:
            is_valid, err, _ = validate_scan_target(item)
            assert not is_valid


# ---------------------------------------------------------------------------
# 2. Vulners and Risky Services Parser Tests
# ---------------------------------------------------------------------------

class TestVulnersParser:
    """Tests parsing of Nmap XML with Vulners script and risky services."""

    @pytest.fixture
    def sample_vulners_xml(self) -> bytes:
        xml_path = Path("samples/sample_nmap_vulners.xml")
        return xml_path.read_bytes()

    def test_parse_sample_vulners_xml(self, sample_vulners_xml):
        findings = NmapScanner.parse_nmap_xml(
            sample_vulners_xml,
            default_target="192.168.1.100",
            asset_criticality="High",
            owner="SecOps",
        )
        assert len(findings) > 0

        # Assert CVEs from Vulners were extracted
        cves = {f.cve for f in findings if f.cve}
        assert "CVE-2021-41773" in cves
        assert "CVE-2021-42013" in cves

        # Verify source is set to nmap-live
        for f in findings:
            assert f.source == "nmap-live"
            assert f.asset == "secops-target.internal"

    def test_risky_services_rules_applied_when_no_cve(self, sample_vulners_xml):
        findings = NmapScanner.parse_nmap_xml(
            sample_vulners_xml,
            default_target="192.168.1.100",
            asset_criticality="High",
        )

        # Port 23: Telnet should be flagged Critical (9.8) with SSH migration advice
        telnet_findings = [f for f in findings if f.port == 23]
        assert len(telnet_findings) == 1
        assert telnet_findings[0].severity == "Critical"
        assert telnet_findings[0].cvss == 9.8
        assert "Telnet open on port 23" in telnet_findings[0].vulnerability
        assert "SSH" in telnet_findings[0].notes

        # Port 21: FTP should be flagged High (7.5) with SFTP advice
        ftp_findings = [f for f in findings if f.port == 21]
        assert len(ftp_findings) == 1
        assert ftp_findings[0].severity == "High"
        assert ftp_findings[0].cvss == 7.5
        assert "FTP exposed" in ftp_findings[0].vulnerability

        # Port 445: SMB should be flagged High (7.5)
        smb_findings = [f for f in findings if f.port == 445]
        assert len(smb_findings) == 1
        assert smb_findings[0].severity == "High"


# ---------------------------------------------------------------------------
# 3. Re-scan Diffing & Remediation State Machine Tests
# ---------------------------------------------------------------------------

class TestRescanDiff:
    """Verifies deduplication, remediation (mitigation), and scan logging."""

    @pytest.fixture
    def memory_db(self):
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        init_db(conn)
        yield conn
        conn.close()

    def test_initial_scan_inserts_open_findings(self, memory_db):
        initial_findings = [
            Finding(
                asset="192.168.1.50",
                vulnerability="Telnet open on port 23",
                port=23,
                severity="Critical",
                cvss=9.8,
                status="Open",
                owner="NetSec",
            ),
            Finding(
                asset="192.168.1.50",
                vulnerability="Apache CVE-2021-41773",
                cve="CVE-2021-41773",
                port=80,
                severity="High",
                cvss=7.5,
                status="Open",
                owner="AppSec",
            ),
        ]

        result = reconcile_scan_results(
            memory_db,
            target="192.168.1.50",
            scanned_findings=initial_findings,
            user="Analyst-1",
        )
        assert result["new"] == 2
        assert result["mitigated"] == 0
        assert result["unchanged"] == 0

        df = load_findings(memory_db)
        assert len(df) == 2
        assert set(df["status"]) == {"Open"}

        # Verify scan_log entry was recorded
        logs = get_scan_logs(memory_db)
        assert len(logs) == 1
        assert logs.iloc[0]["target"] == "192.168.1.50"
        assert logs.iloc[0]["new_count"] == 2

    def test_rescan_mitigates_closed_port_and_preserves_unchanged(self, memory_db):
        # Scan 1: Two vulnerabilities open
        scan1 = [
            Finding(
                asset="192.168.1.50",
                vulnerability="Telnet open on port 23",
                port=23,
                severity="Critical",
                cvss=9.8,
                status="Open",
                owner="NetSec",
                notes="Ticket SEC-101",
            ),
            Finding(
                asset="192.168.1.50",
                vulnerability="Apache CVE-2021-41773",
                cve="CVE-2021-41773",
                port=80,
                severity="High",
                cvss=7.5,
                status="Open",
                owner="AppSec",
                notes="Under patch testing",
            ),
        ]
        reconcile_scan_results(memory_db, "192.168.1.50", scan1)

        # Scan 2: Telnet (port 23) was patched/closed! Only Apache on port 80 remains,
        # plus a brand new service on port 443 is discovered.
        scan2 = [
            Finding(
                asset="192.168.1.50",
                vulnerability="Apache CVE-2021-41773",
                cve="CVE-2021-41773",
                port=80,
                severity="High",
                cvss=7.5,
                status="Open",
            ),
            Finding(
                asset="192.168.1.50",
                vulnerability="New HTTPS service on port 443",
                port=443,
                severity="Medium",
                cvss=5.0,
                status="Open",
            ),
        ]

        result = reconcile_scan_results(memory_db, "192.168.1.50", scan2)
        assert result["new"] == 1        # Port 443 is new
        assert result["mitigated"] == 1  # Port 23 was auto-mitigated
        assert result["unchanged"] == 1  # Port 80 was unchanged

        df = load_findings(memory_db)
        assert len(df) == 3

        # Port 23 must now be Mitigated with note
        telnet = df[df["port"] == 23].iloc[0]
        assert telnet["status"] == "Mitigated"
        assert "Auto-Mitigated" in telnet["notes"]
        assert "Ticket SEC-101" in telnet["notes"]

        # Port 80 must retain original owner and notes
        apache = df[df["port"] == 80].iloc[0]
        assert apache["status"] == "Open"
        assert apache["owner"] == "AppSec"
        assert apache["notes"] == "Under patch testing"

        # Port 443 must be newly added as Open
        https = df[df["port"] == 443].iloc[0]
        assert https["status"] == "Open"
        assert https["port"] == 443
