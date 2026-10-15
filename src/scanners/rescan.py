"""
src/scanners/rescan.py
======================
Re-scan deduplication, diffing, and remediation state machine.

Deduplicates findings by (host, port, CVE/check ID).
- Disappeared findings -> marked 'Mitigated' with current date.
- Brand new findings -> inserted as 'Open' with SLA deadline.
- Unchanged findings -> retain existing owner, status, and analyst notes.
- Logs every scan to scan_log table.
"""

from __future__ import annotations

import sqlite3
from datetime import date
from typing import Any

from src.scanners.base import Finding


def _make_key(asset: str, port: int | None, cve: str, vulnerability: str) -> tuple[str, int, str]:
    """Unique finding identifier: (asset, port, cve or vulnerability description)."""
    clean_asset = str(asset or "").strip()
    clean_port = int(port) if port is not None else 0
    clean_cve = str(cve or "").strip().upper()
    identifier = clean_cve if clean_cve else str(vulnerability or "").strip()
    return (clean_asset, clean_port, identifier)


def reconcile_scan_results(
    conn: sqlite3.Connection,
    target: str,
    scanned_findings: list[Finding],
    scanner_name: str = "Nmap Vulners Scanner",
    user: str = "Security Analyst",
) -> dict[str, int]:
    """
    Apply re-scan diffing logic against the SQLite risk register.

    Parameters
    ----------
    conn:
        SQLite connection to vuln_dashboard.db.
    target:
        The target IP address scanned.
    scanned_findings:
        List of Finding objects returned by the scanner.
    scanner_name:
        Name of the scanner engine.
    user:
        User / operator who initiated the scan.

    Returns
    -------
    dict with counts: {'new': int, 'mitigated': int, 'unchanged': int, 'total': int}
    """
    today_str = date.today().isoformat()

    # Determine all host representations (target IP + any hostname returned)
    assets_in_scan = {target}
    for f in scanned_findings:
        if f.asset:
            assets_in_scan.add(f.asset)

    # Fetch existing findings for these assets
    placeholders = ",".join(["?"] * len(assets_in_scan))
    existing_rows = conn.execute(
        f"""
        SELECT id, asset, port, cve, vulnerability, status, owner, notes, date_found, target_date, overdue
        FROM findings
        WHERE asset IN ({placeholders})
        """,
        list(assets_in_scan),
    ).fetchall()

    existing_by_key: dict[tuple[str, int, str], sqlite3.Row] = {}
    for row in existing_rows:
        key = _make_key(row["asset"], row["port"], row["cve"], row["vulnerability"])
        existing_by_key[key] = row

    new_keys = set()
    for f in scanned_findings:
        key = _make_key(f.asset, f.port, f.cve, f.vulnerability)
        new_keys.add(key)

    new_count = 0
    unchanged_count = 0
    mitigated_count = 0

    # 1. Check for mitigated findings (previously open, but missing from current scan)
    for key, row in existing_by_key.items():
        if row["status"] in ("Open", "In Progress"):
            if key not in new_keys:
                # Vulnerability was fixed / port was closed
                orig_notes = row["notes"] or ""
                auto_note = f"[Auto-Mitigated {today_str}: no longer detected in re-scan]"
                updated_notes = f"{orig_notes} | {auto_note}".strip(" |")

                conn.execute(
                    """
                    UPDATE findings
                    SET status='Mitigated', overdue=0, notes=?
                    WHERE id=?
                    """,
                    (updated_notes, row["id"]),
                )
                mitigated_count += 1

    # 2. Process findings from the current scan
    insert_rows: list[dict[str, Any]] = []

    for f in scanned_findings:
        key = _make_key(f.asset, f.port, f.cve, f.vulnerability)
        if key in existing_by_key:
            row = existing_by_key[key]
            # Existing finding: keep owner, status, notes
            unchanged_count += 1
            # If finding was previously marked Mitigated but reappeared, reopen it
            if row["status"] == "Mitigated":
                reopen_note = f"[Reopened {today_str}: re-detected during scan]"
                curr_notes = f"{row['notes'] or ''} | {reopen_note}".strip(" |")
                conn.execute(
                    """
                    UPDATE findings
                    SET status='Open', notes=?
                    WHERE id=?
                    """,
                    (curr_notes, row["id"]),
                )
        else:
            # Brand new finding
            new_count += 1
            f_dict = f.to_dict()
            insert_rows.append(f_dict)

    # Insert brand new findings
    if insert_rows:
        keys = [
            "asset", "asset_type", "asset_criticality", "vulnerability",
            "cve", "cvss", "severity", "risk_score", "service", "port",
            "owner", "status", "date_found", "target_date", "overdue",
            "notes", "nist_csf", "iso_control", "source",
        ]
        placeholders_sql = ", ".join(["?"] * len(keys))
        sql = f"INSERT INTO findings ({', '.join(keys)}) VALUES ({placeholders_sql})"
        conn.executemany(sql, [[row.get(k) for k in keys] for row in insert_rows])

    # 3. Log this scan execution into scan_log table
    scan_status = "Success"
    total_found = len(scanned_findings)
    conn.execute(
        """
        INSERT INTO scan_log (
            target, scanner, scan_time, status, findings_count,
            new_count, mitigated_count, unchanged_count, user
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target,
            scanner_name,
            today_str,
            scan_status,
            total_found,
            new_count,
            mitigated_count,
            unchanged_count,
            user,
        ),
    )

    conn.commit()

    return {
        "new": new_count,
        "mitigated": mitigated_count,
        "unchanged": unchanged_count,
        "total": total_found,
    }
