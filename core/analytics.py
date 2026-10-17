"""
core/analytics.py
=================
Analytics and data transformation layer for VulnWatch.
Separates dashboard presentation from business and scoring logic.
"""

from __future__ import annotations

import sqlite3
from datetime import date, timedelta
from typing import Any

import pandas as pd


def normalize_status(status: str, team_mode: bool = False) -> str:
    """
    Normalize status string for display.
    In personal mode:
      'Mitigated' -> 'Fixed'
      'Accepted'  -> 'Ignored'
    In team mode:
      Retains 'Open', 'In Progress', 'Mitigated', 'Accepted'
    """
    raw = str(status or "").strip()
    lower = raw.lower()
    if not team_mode:
        if lower in ("fixed", "mitigated"):
            return "Fixed"
        if lower in ("ignored", "accepted"):
            return "Ignored"
        return "Open"
    else:
        if lower in ("fixed", "mitigated"):
            return "Mitigated"
        if lower in ("ignored", "accepted"):
            return "Accepted"
        if lower == "in progress":
            return "In Progress"
        return "Open"


def get_personal_kpis(df: pd.DataFrame) -> dict[str, Any]:
    """Compute high-level summary metrics for Personal Mode."""
    if df.empty:
        return {
            "total_devices": 0,
            "total_findings": 0,
            "open_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "fixed_count": 0,
            "ignored_count": 0,
        }

    # In personal mode: 'Open' is open; 'Fixed'/'Mitigated' and 'Ignored'/'Accepted' are non-open
    is_open = ~df["status"].str.lower().isin(["fixed", "mitigated", "ignored", "accepted"])
    open_df = df[is_open]

    return {
        "total_devices": int(df["asset"].nunique()),
        "total_findings": len(df),
        "open_findings": len(open_df),
        "critical_count": int((open_df["severity"] == "Critical").sum()),
        "high_count": int((open_df["severity"] == "High").sum()),
        "medium_count": int((open_df["severity"] == "Medium").sum()),
        "low_count": int((open_df["severity"] == "Low").sum()),
        "fixed_count": int(df["status"].str.lower().isin(["fixed", "mitigated"]).sum()),
        "ignored_count": int(df["status"].str.lower().isin(["ignored", "accepted"]).sum()),
    }


def get_what_changed_summary(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """
    Retrieve details of the most recent scan execution to show what changed.
    """
    row = conn.execute(
        "SELECT target, scanner, scan_time, status, findings_count, new_count, mitigated_count, unchanged_count "
        "FROM scan_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not row:
        return None

    return {
        "target": row["target"],
        "scanner": row["scanner"],
        "scan_time": row["scan_time"],
        "status": row["status"],
        "findings_count": row["findings_count"],
        "new_count": row["new_count"],
        "fixed_count": row["mitigated_count"],
        "unchanged_count": row["unchanged_count"],
    }


def get_device_inventory(df: pd.DataFrame, host_scan_df: pd.DataFrame | None = None) -> list[dict[str, Any]]:
    """
    Produce a device-centric summary across all tracked hardware.
    """
    if df.empty:
        return []

    last_scanned_map: dict[str, str] = {}
    if host_scan_df is not None and not host_scan_df.empty:
        for _, row in host_scan_df.iterrows():
            last_scanned_map[str(row.get("target", ""))] = str(row.get("last_scanned", ""))

    devices: list[dict[str, Any]] = []
    for asset, group in df.groupby("asset"):
        asset_str = str(asset)
        asset_type = group["asset_type"].iloc[0] if "asset_type" in group.columns and pd.notna(group["asset_type"].iloc[0]) else "Device"
        
        is_open = ~group["status"].str.lower().isin(["fixed", "mitigated", "ignored", "accepted"])
        open_items = group[is_open]

        # Gather distinct services/ports
        services = set()
        for _, r in group.iterrows():
            svc = str(r.get("service") or "").strip()
            port = r.get("port")
            if port and svc:
                services.add(f"{svc}:{port}")
            elif port:
                services.add(f"port {port}")
            elif svc:
                services.add(svc)

        devices.append({
            "asset": asset_str,
            "asset_type": asset_type,
            "total_findings": len(group),
            "open_findings": len(open_items),
            "critical": int((open_items["severity"] == "Critical").sum()),
            "high": int((open_items["severity"] == "High").sum()),
            "medium": int((open_items["severity"] == "Medium").sum()),
            "low": int((open_items["severity"] == "Low").sum()),
            "services": sorted(list(services)),
            "last_scanned": last_scanned_map.get(asset_str, "Recorded in register"),
        })

    # Sort devices by open critical then high findings descending
    devices.sort(key=lambda d: (d["critical"], d["high"], d["open_findings"]), reverse=True)
    return devices


def get_team_kpis(df: pd.DataFrame) -> dict[str, Any]:
    """Compute enterprise metrics for Team Mode."""
    if df.empty:
        return {
            "total": 0,
            "n_open": 0,
            "n_critical": 0,
            "n_high": 0,
            "n_overdue": 0,
            "sla_pct": 100.0,
            "mttr": "N/A",
        }

    open_df = df[df["status"].isin(["Open", "In Progress"])]
    n_overdue = int(df["overdue"].sum()) if "overdue" in df.columns else 0

    active = df[df["status"].isin(["Open", "In Progress", "Mitigated", "Accepted"])]
    if len(active) and "overdue" in df.columns:
        n_on_time = len(active[active["overdue"] == 0])
        sla_pct = round(n_on_time / len(active) * 100, 1)
    else:
        sla_pct = 100.0

    mit_df = df[df["status"] == "Mitigated"].copy()
    if not mit_df.empty and "date_found" in mit_df.columns and "target_date" in mit_df.columns:
        mit_df["date_found_dt"] = pd.to_datetime(mit_df["date_found"])
        mit_df["target_dt"] = pd.to_datetime(mit_df["target_date"])
        mttr = round((mit_df["target_dt"] - mit_df["date_found_dt"]).dt.days.mean(), 1)
    else:
        mttr = "N/A"

    return {
        "total": len(df),
        "n_open": len(open_df),
        "n_critical": int((df["severity"] == "Critical").sum()),
        "n_high": int((df["severity"] == "High").sum()),
        "n_overdue": n_overdue,
        "sla_pct": sla_pct,
        "mttr": mttr,
    }


def get_trend_data(df: pd.DataFrame) -> pd.DataFrame:
    """Build 6-month opened vs closed trend DataFrame (Team Mode)."""
    df_copy = df.copy()
    df_copy["date_found_dt"] = pd.to_datetime(df_copy["date_found"])
    df_copy["year_month"] = df_copy["date_found_dt"].dt.to_period("M").astype(str)

    opened = df_copy.groupby("year_month").size().reset_index(name="Opened")
    closed = (
        df_copy[df_copy["status"].isin(["Mitigated", "Accepted", "Fixed"])]
        .groupby("year_month")
        .size()
        .reset_index(name="Closed")
    )
    trend = opened.merge(closed, on="year_month", how="outer").fillna(0).sort_values("year_month")
    return trend.melt("year_month", var_name="Type", value_name="Count")


def get_compliance_nist(df: pd.DataFrame) -> pd.DataFrame:
    """Parse comma-separated NIST functions into long-form DataFrame."""
    rows = []
    for _, r in df.iterrows():
        for f in str(r.get("nist_csf", "")).split(","):
            f = f.strip()
            if f:
                rows.append({"function": f, "severity": r.get("severity", ""), "risk_score": r.get("risk_score", 0.0)})
    return pd.DataFrame(rows)


def get_compliance_iso(df: pd.DataFrame) -> pd.DataFrame:
    """Compute findings distribution across ISO 27001 controls."""
    if "iso_control" not in df.columns:
        return pd.DataFrame(columns=["Control", "Findings"])
    counts = df["iso_control"].value_counts().reset_index()
    counts.columns = ["Control", "Findings"]
    return counts

