"""
core/database.py
================
SQLite persistence layer for the risk register.

Schema
------
findings
  id              INTEGER PRIMARY KEY AUTOINCREMENT
  asset           TEXT NOT NULL          -- hostname / IP
  asset_type      TEXT                   -- Server-Windows | Server-Linux | Workstation | Network
  asset_criticality TEXT DEFAULT 'Medium'-- High | Medium | Low
  vulnerability   TEXT NOT NULL          -- short description
  cve             TEXT                   -- CVE-YYYY-NNNNN
  cvss            REAL                   -- 0.0 – 10.0
  severity        TEXT                   -- Critical | High | Medium | Low
  risk_score      REAL                   -- 0-100 computed
  service         TEXT                   -- apache/2.4.51, openssh/8.9, …
  port            INTEGER
  owner           TEXT                   -- responsible team / person
  status          TEXT DEFAULT 'Open'    -- Open|In Progress|Mitigated|Accepted
  date_found      TEXT                   -- ISO date YYYY-MM-DD
  target_date     TEXT                   -- SLA deadline, ISO date
  overdue         INTEGER DEFAULT 0      -- 0/1 boolean
  notes           TEXT DEFAULT ''
  nist_csf        TEXT                   -- comma-separated functions
  iso_control     TEXT                   -- e.g. A.8.8
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd

DB_PATH = Path("vuln_dashboard.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    """Create tables if they don't exist."""
    if conn is None:
        conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            asset            TEXT    NOT NULL,
            asset_type       TEXT,
            asset_criticality TEXT   DEFAULT 'Medium',
            vulnerability    TEXT    NOT NULL,
            cve              TEXT,
            cvss             REAL,
            severity         TEXT,
            risk_score       REAL,
            service          TEXT,
            port             INTEGER,
            owner            TEXT,
            status           TEXT    DEFAULT 'Open',
            date_found       TEXT,
            target_date      TEXT,
            overdue          INTEGER DEFAULT 0,
            notes            TEXT    DEFAULT '',
            nist_csf         TEXT,
            iso_control      TEXT
        )
        """
    )
    conn.commit()


def clear_db(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM findings")
    conn.commit()


def insert_findings(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    """Bulk-insert a list of finding dicts."""
    if not rows:
        return
    keys = [
        "asset", "asset_type", "asset_criticality", "vulnerability",
        "cve", "cvss", "severity", "risk_score", "service", "port",
        "owner", "status", "date_found", "target_date", "overdue",
        "notes", "nist_csf", "iso_control",
    ]
    placeholders = ", ".join(["?"] * len(keys))
    col_names = ", ".join(keys)
    sql = f"INSERT INTO findings ({col_names}) VALUES ({placeholders})"
    conn.executemany(sql, [[row.get(k) for k in keys] for row in rows])
    conn.commit()


def load_findings(conn: sqlite3.Connection) -> pd.DataFrame:
    """Load all findings into a DataFrame."""
    df = pd.read_sql_query("SELECT * FROM findings ORDER BY risk_score DESC", conn)
    return df


def update_finding(
    conn: sqlite3.Connection,
    finding_id: int,
    status: str,
    owner: str,
    notes: str,
) -> None:
    """Update mutable fields on a single finding."""
    from datetime import date
    from core.scoring import is_overdue, cvss_to_severity

    # Retrieve current row to recompute overdue flag
    row = conn.execute("SELECT severity, date_found FROM findings WHERE id=?", (finding_id,)).fetchone()
    overdue = 0
    if row:
        overdue = int(is_overdue(row["severity"], date.fromisoformat(row["date_found"]), status))

    conn.execute(
        """
        UPDATE findings
        SET status=?, owner=?, notes=?, overdue=?
        WHERE id=?
        """,
        (status, owner, notes, overdue, finding_id),
    )
    conn.commit()


def refresh_overdue_flags(conn: sqlite3.Connection) -> None:
    """Recompute overdue for every open finding (call on app startup)."""
    from datetime import date
    from core.scoring import is_overdue

    rows = conn.execute(
        "SELECT id, severity, date_found, status FROM findings"
    ).fetchall()
    for row in rows:
        overdue = int(is_overdue(row["severity"], date.fromisoformat(row["date_found"]), row["status"]))
        conn.execute("UPDATE findings SET overdue=? WHERE id=?", (overdue, row["id"]))
    conn.commit()
