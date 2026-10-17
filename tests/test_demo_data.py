"""
tests/test_demo_data.py
=======================
Unit tests for core/demo_data.py personal findings generator.
"""

from __future__ import annotations

import pytest
from core.demo_data import generate_demo_findings, HOSTS, CVE_POOL


def test_hosts_personal_setup():
    assert len(HOSTS) == 5
    assets = [h["asset"] for h in HOSTS]
    assert "thinkpad-laptop" in assets
    assert "raspberrypi-4b" in assets
    assert "homelab-server" in assets
    assert "openwrt-router" in assets
    assert "dev-ubuntu-vm" in assets


def test_generate_demo_findings_count():
    findings = generate_demo_findings(target_count=50, seed=123)
    assert len(findings) == 50


def test_generate_demo_findings_schema():
    findings = generate_demo_findings(target_count=10, seed=42)
    required_keys = {
        "asset", "asset_type", "asset_criticality", "vulnerability",
        "cve", "cvss", "severity", "risk_score", "service", "port",
        "owner", "status", "date_found", "target_date", "overdue",
        "notes", "nist_csf", "iso_control",
    }
    for f in findings:
        assert required_keys.issubset(f.keys())
        assert 0.0 <= f["cvss"] <= 10.0
        assert 0.0 <= f["risk_score"] <= 100.0
        assert f["severity"] in ["Critical", "High", "Medium", "Low", "Informational"]
        assert f["status"] in ["Open", "Fixed", "Ignored", "In Progress", "Mitigated", "Accepted"]
        assert f["overdue"] in (0, 1)


def test_generate_demo_findings_reproducible_seed():
    f1 = generate_demo_findings(target_count=20, seed=99)
    f2 = generate_demo_findings(target_count=20, seed=99)
    assert f1 == f2
