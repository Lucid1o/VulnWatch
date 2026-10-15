"""
core/database.py
================
SQLite persistence layer for the risk register and scan logs.

Schema
------
findings
  id                INTEGER PRIMARY KEY AUTOINCREMENT
  asset             TEXT NOT NULL          -- hostname / IP
  asset_type        TEXT                   -- Server-Windows | Server-Linux | Workstation | Network
  asset_criticality TEXT DEFAULT 'Medium'  -- High | Medium | Low
  vulnerability     TEXT NOT NULL          -- short description
  cve               TEXT                   -- CVE-YYYY-NNNNN
  cvss              REAL                   -- 0.0 - 10.0
  severity          TEXT                   -- Critical | High | Medium | Low
  risk_score        REAL                   -- 0-100 computed
  service           TEXT                   -- apache/2.4.51, openssh/8.9, ...
  port              INTEGER
  owner             TEXT                   -- responsible team / person
  status            TEXT DEFAULT 'Open'    -- Open|In Progress|Mitigated|Accepted
  date_found        TEXT                   -- ISO date YYYY-MM-DD
  target_date       TEXT                   -- SLA deadline, ISO date
  overdue           INTEGER DEFAULT 0      -- 0/1 boolean
  notes             TEXT DEFAULT ''
  nist_csf          TEXT                   -- comma-separated functions
  iso_control       TEXT                   -- e.g. A.8.8
  source            TEXT DEFAULT 'demo'    -- demo | nmap-live | csv | nmap-upload

scan_log
  id                INTEGER PRIMARY KEY AUTOINCREMENT
  target            TEXT NOT NULL
  scanner           TEXT NOT NULL
  scan_time         TEXT NOT NULL
  status            TEXT NOT NULL
  findings_count    INTEGER DEFAULT 0
  new_count         INTEGER DEFAULT 0
  mitigated_count   INTEGER DEFAULT 0
  unchanged_count   INTEGER DEFAULT 0
  user              TEXT DEFAULT 'Security Analyst'
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd

DB_PATH = Path("vuln_dashboard.db")


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    target_path = Path(db_path) if db_path else DB_PATH
    conn = sqlite3.connect(target_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    """Create tables if they don't exist and run non-destructive migrations."""
    if conn is None:
        conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            asset             TEXT    NOT NULL,
            asset_type        TEXT,
            asset_criticality TEXT   DEFAULT 'Medium',
            vulnerability     TEXT    NOT NULL,
            cve               TEXT,
            cvss              REAL,
            severity          TEXT,
            risk_score        REAL,
            service           TEXT,
            port              INTEGER,
            owner             TEXT,
            status            TEXT    DEFAULT 'Open',
            date_found        TEXT,
            target_date       TEXT,
            overdue           INTEGER DEFAULT 0,
            notes             TEXT    DEFAULT '',
            nist_csf          TEXT,
            iso_control       TEXT,
            source            TEXT    DEFAULT 'demo'
        )
        """
    )

    # Non-destructive migration: ensure source column exists on older databases
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN source TEXT DEFAULT 'demo'")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Scan history log table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_log (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            target           TEXT    NOT NULL,
            scanner          TEXT    NOT NULL,
            scan_time        TEXT    NOT NULL,
            status           TEXT    NOT NULL,
            findings_count   INTEGER DEFAULT 0,
            new_count        INTEGER DEFAULT 0,
            mitigated_count  INTEGER DEFAULT 0,
            unchanged_count  INTEGER DEFAULT 0,
            user             TEXT    DEFAULT 'Security Analyst'
        )
        """
    )
    conn.commit()


def clear_db(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM findings")
    conn.execute("DELETE FROM scan_log")
    conn.commit()


def insert_findings(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    """Bulk-insert a list of finding dicts."""
    if not rows:
        return
    keys = [
        "asset", "asset_type", "asset_criticality", "vulnerability",
        "cve", "cvss", "severity", "risk_score", "service", "port",
        "owner", "status", "date_found", "target_date", "overdue",
        "notes", "nist_csf", "iso_control", "source",
    ]
    placeholders = ", ".join(["?"] * len(keys))
    col_names = ", ".join(keys)
    sql = f"INSERT INTO findings ({col_names}) VALUES ({placeholders})"

    # Default missing source to 'demo'
    formatted_rows = []
    for row in rows:
        r = [row.get(k) for k in keys]
        if r[-1] is None:
            r[-1] = "demo"
        formatted_rows.append(r)

    conn.executemany(sql, formatted_rows)
    conn.commit()


def load_findings(conn: sqlite3.Connection, source_filter: str | None = None) -> pd.DataFrame:
    """Load findings into a DataFrame, optionally filtered by source."""
    if source_filter:
        df = pd.read_sql_query(
            "SELECT * FROM findings WHERE source = ? ORDER BY risk_score DESC",
            conn,
            params=(source_filter,),
        )
    else:
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
    from core.scoring import is_overdue

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


def get_scan_logs(conn: sqlite3.Connection, limit: int = 50) -> pd.DataFrame:
    """Retrieve scan execution logs ordered by most recent."""
    return pd.read_sql_query(
        "SELECT * FROM scan_log ORDER BY id DESC LIMIT ?",
        conn,
        params=(limit,),
    )


def get_host_last_scanned(conn: sqlite3.Connection) -> pd.DataFrame:
    """Retrieve the latest scan timestamp and summary per target."""
    sql = """
        SELECT
            target,
            MAX(scan_time) AS last_scanned,
            scanner,
            COUNT(*) AS total_scans
        FROM scan_log
        GROUP BY target
        ORDER BY last_scanned DESC
    """
    return pd.read_sql_query(sql, conn)
