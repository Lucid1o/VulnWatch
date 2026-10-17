"""
tests/test_config_and_analytics.py
==================================
Unit tests for core/config.py and core/analytics.py.
"""

from __future__ import annotations

import sqlite3
import pandas as pd
import pytest

from core.config import load_config, is_team_mode_enabled
from core.analytics import (
    normalize_status,
    get_personal_kpis,
    get_what_changed_summary,
    get_device_inventory,
)
from core.demo_data import generate_demo_findings
from core.database import init_db, insert_findings


def test_config_load_default():
    cfg = load_config()
    assert "team_mode" in cfg
    assert isinstance(cfg["team_mode"], bool)


def test_normalize_status():
    # Personal mode
    assert normalize_status("Mitigated", team_mode=False) == "Fixed"
    assert normalize_status("Accepted", team_mode=False) == "Ignored"
    assert normalize_status("Fixed", team_mode=False) == "Fixed"
    assert normalize_status("Ignored", team_mode=False) == "Ignored"
    assert normalize_status("Open", team_mode=False) == "Open"

    # Team mode
    assert normalize_status("Mitigated", team_mode=True) == "Mitigated"
    assert normalize_status("Accepted", team_mode=True) == "Accepted"
    assert normalize_status("In Progress", team_mode=True) == "In Progress"


def test_personal_kpis():
    findings = generate_demo_findings(target_count=20, seed=42, team_mode=False)
    df = pd.DataFrame(findings)
    kpis = get_personal_kpis(df)
    assert kpis["total_devices"] <= 5
    assert kpis["total_findings"] == 20
    assert kpis["open_findings"] >= 0
    assert kpis["critical_count"] >= 0


def test_device_inventory():
    findings = generate_demo_findings(target_count=25, seed=42, team_mode=False)
    df = pd.DataFrame(findings)
    devices = get_device_inventory(df)
    assert len(devices) > 0
    assert any(d["asset"] == "thinkpad-laptop" for d in devices)
    for dev in devices:
        assert "asset" in dev
        assert "asset_type" in dev
        assert "open_findings" in dev
        assert "services" in dev


def test_what_changed_summary():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)

    # Empty log
    assert get_what_changed_summary(conn) is None

    # Insert a scan log entry
    conn.execute(
        """
        INSERT INTO scan_log (target, scanner, scan_time, status, findings_count, new_count, mitigated_count, unchanged_count, user)
        VALUES ('192.168.1.50', 'Nmap Vulners Scanner', '2026-10-17', 'Success', 5, 2, 1, 2, 'Local User')
        """
    )
    conn.commit()

    diff = get_what_changed_summary(conn)
    assert diff is not None
    assert diff["target"] == "192.168.1.50"
    assert diff["new_count"] == 2
    assert diff["fixed_count"] == 1
    assert diff["unchanged_count"] == 2
    conn.close()
