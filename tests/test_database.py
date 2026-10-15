"""
tests/test_database.py
======================
Unit tests for core/database.py SQLite operations.
"""

from __future__ import annotations

import sqlite3
from datetime import date, timedelta
import pytest
import pandas as pd

from core.database import (
    init_db,
    clear_db,
    insert_findings,
    load_findings,
    update_finding,
    refresh_overdue_flags,
)


@pytest.fixture
def memory_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    yield conn
    conn.close()


def test_init_db_creates_table(memory_db):
    cursor = memory_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
    )
    assert cursor.fetchone() is not None


def test_insert_and_load_findings(memory_db):
    sample = [
        {
            "asset": "SRV-01",
            "asset_type": "Server-Linux",
            "asset_criticality": "High",
            "vulnerability": "Test Vulnerability",
            "cve": "CVE-2023-1234",
            "cvss": 9.5,
            "severity": "Critical",
            "risk_score": 98.0,
            "service": "openssh/8.2",
            "port": 22,
            "owner": "SecOps",
            "status": "Open",
            "date_found": "2024-01-01",
            "target_date": "2024-01-08",
            "overdue": 1,
            "notes": "Testing notes",
            "nist_csf": "Protect",
            "iso_control": "A.8.8",
        }
    ]
    insert_findings(memory_db, sample)
    df = load_findings(memory_db)
    assert len(df) == 1
    assert df.iloc[0]["asset"] == "SRV-01"
    assert df.iloc[0]["cvss"] == 9.5
    assert df.iloc[0]["overdue"] == 1


def test_clear_db(memory_db):
    sample = [
        {
            "asset": "SRV-01",
            "asset_type": "Server-Linux",
            "asset_criticality": "High",
            "vulnerability": "Test Vuln",
            "cve": "CVE-2023-1111",
            "cvss": 7.0,
            "severity": "High",
            "risk_score": 75.0,
            "service": "apache",
            "port": 80,
            "owner": "AppSec",
            "status": "Open",
            "date_found": "2024-01-01",
            "target_date": "2024-01-31",
            "overdue": 0,
            "notes": "",
            "nist_csf": "Identify",
            "iso_control": "A.8.8",
        }
    ]
    insert_findings(memory_db, sample)
    assert len(load_findings(memory_db)) == 1

    clear_db(memory_db)
    assert len(load_findings(memory_db)) == 0


def test_update_finding(memory_db):
    sample = [
        {
            "asset": "SRV-02",
            "asset_type": "Server-Windows",
            "asset_criticality": "Medium",
            "vulnerability": "Old Vuln",
            "cve": "CVE-2023-9999",
            "cvss": 9.0,
            "severity": "Critical",
            "risk_score": 90.0,
            "service": "smb",
            "port": 445,
            "owner": "SysAdmin",
            "status": "Open",
            "date_found": "2023-01-01",
            "target_date": "2023-01-08",
            "overdue": 1,
            "notes": "Initial note",
            "nist_csf": "Protect",
            "iso_control": "A.8.8",
        }
    ]
    insert_findings(memory_db, sample)
    row_id = memory_db.execute("SELECT id FROM findings WHERE asset='SRV-02'").fetchone()["id"]

    # When marked Mitigated, overdue should become 0
    update_finding(memory_db, row_id, status="Mitigated", owner="NewOwner", notes="Patched today")

    updated = memory_db.execute("SELECT * FROM findings WHERE id=?", (row_id,)).fetchone()
    assert updated["status"] == "Mitigated"
    assert updated["owner"] == "NewOwner"
    assert updated["notes"] == "Patched today"
    assert updated["overdue"] == 0


def test_refresh_overdue_flags(memory_db):
    old_date = (date.today() - timedelta(days=20)).isoformat()
    sample = [
        {
            "asset": "SRV-03",
            "asset_type": "Server-Linux",
            "asset_criticality": "High",
            "vulnerability": "Critical Finding",
            "cve": "CVE-2024-0001",
            "cvss": 9.5,
            "severity": "Critical",
            "risk_score": 95.0,
            "service": "ssh",
            "port": 22,
            "owner": "LinuxTeam",
            "status": "Open",
            "date_found": old_date,
            "target_date": (date.today() - timedelta(days=13)).isoformat(),
            "overdue": 0,  # Deliberately stale
            "notes": "",
            "nist_csf": "Identify",
            "iso_control": "A.8.8",
        }
    ]
    insert_findings(memory_db, sample)
    refresh_overdue_flags(memory_db)

    row = memory_db.execute("SELECT overdue FROM findings WHERE asset='SRV-03'").fetchone()
    assert row["overdue"] == 1
