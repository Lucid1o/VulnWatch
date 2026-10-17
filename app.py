"""
app.py
======
VulnWatch — Personal Vulnerability Scanner & Risk Tracker
Entry point: streamlit run app.py
"""

from __future__ import annotations

import sqlite3
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.analytics import (
    get_compliance_iso,
    get_compliance_nist,
    get_device_inventory,
    get_personal_kpis,
    get_team_kpis,
    get_trend_data,
    get_what_changed_summary,
    normalize_status,
)
from core.config import is_team_mode_enabled, load_config
from core.database import (
    clear_db,
    get_connection,
    get_host_last_scanned,
    get_scan_logs,
    init_db,
    insert_findings,
    load_findings,
    refresh_overdue_flags,
    update_finding,
)
from core.demo_data import generate_demo_findings
from core.exports import (
    export_excel,
    export_markdown_summary,
    export_personal_findings_markdown,
)
from core.parsers import parse_csv, parse_nmap_xml
from core.scoring import compute_risk_score, cvss_to_severity, is_overdue, sla_target_date
from src.scanners.nmap_scanner import NmapScanner
from src.scanners.rescan import reconcile_scan_results
from src.scanners.validator import validate_scan_target

# ============================================================
# PAGE CONFIG (must be first Streamlit call)
# ============================================================
st.set_page_config(
    page_title="VulnWatch",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# GLOBAL CSS
# ============================================================
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #e2e8f0;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f172a 0%, #1a2744 100%);
    border-right: 1px solid rgba(99,102,241,0.2);
}
[data-testid="stSidebar"] * { color: #cbd5e1 !important; }
[data-testid="stSidebar"] .stRadio > label { color: #94a3b8 !important; font-size: 0.8rem; }

.kpi-card {
    background: linear-gradient(135deg, rgba(30,41,59,0.9) 0%, rgba(15,23,42,0.9) 100%);
    border: 1px solid rgba(99,102,241,0.3);
    border-radius: 12px;
    padding: 18px 20px;
    text-align: center;
    backdrop-filter: blur(10px);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.kpi-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(99,102,241,0.2);
}
.kpi-value {
    font-size: 2.1rem;
    font-weight: 700;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    line-height: 1.1;
}
.kpi-value.danger { background: linear-gradient(135deg, #ef4444, #dc2626); -webkit-background-clip: text; background-clip: text; }
.kpi-value.warning { background: linear-gradient(135deg, #f59e0b, #d97706); -webkit-background-clip: text; background-clip: text; }
.kpi-value.success { background: linear-gradient(135deg, #22c55e, #16a34a); -webkit-background-clip: text; background-clip: text; }
.kpi-label {
    font-size: 0.74rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94a3b8;
    margin-top: 6px;
}

.device-card {
    background: rgba(30,41,59,0.7);
    border: 1px solid rgba(99,102,241,0.25);
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 12px;
}

.section-header {
    font-size: 1.35rem;
    font-weight: 700;
    color: #e2e8f0;
    border-left: 4px solid #6366f1;
    padding-left: 12px;
    margin: 24px 0 16px 0;
}

.badge-critical { background:#dc2626; color:#fff; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600; }
.badge-high     { background:#ea580c; color:#fff; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600; }
.badge-medium   { background:#ca8a04; color:#fff; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600; }
.badge-low      { background:#16a34a; color:#fff; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600; }

.stButton > button {
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 0.5rem 1.4rem;
    transition: all 0.2s ease;
}
.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 15px rgba(99,102,241,0.4);
}
.stDownloadButton > button {
    background: linear-gradient(135deg, #059669, #10b981);
    color: white !important;
    border: none;
    border-radius: 8px;
    font-weight: 600;
}

.alert-box {
    border-radius: 10px;
    padding: 12px 16px;
    margin: 10px 0;
    border-left: 4px solid;
}
.alert-danger  { background: rgba(220,38,38,0.12);  border-color: #dc2626; }
.alert-warning { background: rgba(234,179,8,0.12);  border-color: #eab308; }
.alert-info    { background: rgba(99,102,241,0.12); border-color: #6366f1; }
.alert-success { background: rgba(34,197,94,0.12);  border-color: #22c55e; }

#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 1.5rem; }

.app-title {
    font-size: 1.8rem;
    font-weight: 800;
    background: linear-gradient(135deg, #6366f1, #a78bfa, #38bdf8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
.app-subtitle { font-size: 0.78rem; color: #64748b; margin-top: -4px; }
</style>
""",
    unsafe_allow_html=True,
)

# ============================================================
# COLOUR MAPS & THEMES
# ============================================================
SEV_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#eab308",
    "Low": "#22c55e",
    "Informational": "#64748b",
}
STATUS_COLORS_TEAM = {
    "Open": "#dc2626",
    "In Progress": "#f59e0b",
    "Mitigated": "#22c55e",
    "Accepted": "#6366f1",
}
STATUS_COLORS_PERSONAL = {
    "Open": "#dc2626",
    "Fixed": "#22c55e",
    "Ignored": "#64748b",
}


def _plotly_layout(fig: go.Figure, title: str = "") -> go.Figure:
    fig.update_layout(
        title=title,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#cbd5e1", family="Inter"),
        margin=dict(l=10, r=10, t=36, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)", font_color="#94a3b8"),
    )
    fig.update_xaxes(gridcolor="rgba(99,102,241,0.1)", zerolinecolor="rgba(0,0,0,0)")
    fig.update_yaxes(gridcolor="rgba(99,102,241,0.1)", zerolinecolor="rgba(0,0,0,0)")
    return fig


def kpi_card(value: str | int | float, label: str, variant: str = "default") -> str:
    val_class = {"danger": "danger", "warning": "warning", "success": "success"}.get(variant, "")
    return f"""
    <div class="kpi-card">
        <div class="kpi-value {val_class}">{value}</div>
        <div class="kpi-label">{label}</div>
    </div>
    """


# ============================================================
# DB & CONFIG INITIALISATION
# ============================================================
@st.cache_resource
def _get_conn() -> sqlite3.Connection:
    conn = get_connection()
    init_db(conn)
    return conn


conn = _get_conn()
config = load_config()
config_team_enabled = bool(config.get("team_mode", False))


def _load_df() -> pd.DataFrame:
    refresh_overdue_flags(conn)
    scope = st.session_state.get("scope_filter_radio", "All Findings")
    if scope in ("Sample Data Only", "Demo Data Only"):
        return load_findings(conn, source_filter="demo")
    elif scope == "Live Scans Only":
        return load_findings(conn, source_filter="nmap-live")
    return load_findings(conn)


def _seed_demo_if_empty(is_team: bool) -> None:
    df = load_findings(conn)
    if df.empty:
        with st.spinner("🔄 Loading sample data…"):
            count = 50 if is_team else 25
            findings = generate_demo_findings(count, seed=42, team_mode=is_team)
            insert_findings(conn, findings)
        st.rerun()


# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown(
        """
        <div style="padding:6px 0 16px 0;">
            <div class="app-title">🛡️ VulnWatch</div>
            <div class="app-subtitle">Personal Vulnerability Scanner</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar toggle for team features
    if "team_mode" not in st.session_state:
        st.session_state["team_mode"] = config_team_enabled

    team_mode = st.toggle(
        "👥 Team Mode",
        value=st.session_state["team_mode"],
        key="team_mode_active_toggle",
        help="Toggle between Personal Mode (home lab / personal devices) and Team Mode (enterprise-style risk register, SLAs, executive summary).",
    )
    st.session_state["team_mode"] = team_mode

    st.markdown("---")

    # Navigation choices dependent on mode
    if not team_mode:
        pages = [
            "🏠 Overview",
            "💻 Devices",
            "🔍 Findings",
            "🎯 Run Scan",
            "📜 History",
        ]
    else:
        pages = [
            "📊 Executive Summary",
            "📋 Risk Register",
            "🔧 Remediation Tracker",
            "📐 Compliance View",
            "🎯 Live Network Scan",
            "📥 Data Ingestion",
            "📤 Export Reports",
        ]

    page = st.radio("Navigation", pages, label_visibility="collapsed")

    st.markdown("---")
    st.markdown("#### 🔍 Scope Filter")
    st.radio(
        "Scope Filter",
        ["All Findings", "Sample Data Only", "Live Scans Only"],
        key="scope_filter_radio",
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("#### 🗄️ Data Management")

    df_check = load_findings(conn)
    if df_check.empty:
        st.warning("No data loaded. Click below to load sample home lab data.")
        if st.button("Load Sample Data", key="sidebar_demo"):
            findings = generate_demo_findings(25 if not team_mode else 50, seed=42, team_mode=team_mode)
            insert_findings(conn, findings)
            st.rerun()
    else:
        live_count = len(df_check[df_check["source"] == "nmap-live"]) if "source" in df_check.columns else 0
        sample_count = len(df_check[df_check["source"] != "nmap-live"]) if "source" in df_check.columns else len(df_check)
        st.caption(f"📊 **{len(df_check)}** total ({sample_count} sample, {live_count} live)")
        if sample_count > 0:
            st.caption("🏷️ *Sample data loaded*")
        if st.button("🔄 Reset to Sample Data", key="sidebar_reset"):
            clear_db(conn)
            findings = generate_demo_findings(25 if not team_mode else 50, seed=42, team_mode=team_mode)
            insert_findings(conn, findings)
            st.rerun()

    st.markdown("---")
    st.markdown(
        "<div style='font-size:0.7rem;color:#475569;text-align:center;'>"
        "VulnWatch v1.0 · Personal Scanner</div>",
        unsafe_allow_html=True,
    )

# Seed if empty
_seed_demo_if_empty(team_mode)


# ============================================================
# ============================================================
# PERSONAL MODE PAGES
# ============================================================
# ============================================================

if not team_mode:

    # ────────────────────────────────────────────────────────
    # 1. OVERVIEW PAGE
    # ────────────────────────────────────────────────────────
    if page == "🏠 Overview":
        st.markdown('<div class="section-header">Overview</div>', unsafe_allow_html=True)

        df = _load_df()
        if df.empty:
            st.info("No findings loaded. Run a scan in **Run Scan** or load sample data from the sidebar.")
            st.stop()

        # Banner for sample data
        has_sample = (df["source"] == "demo").any() if "source" in df.columns else False
        if has_sample:
            st.markdown(
                '<div class="alert-box alert-info">ℹ️ <b>Sample Data Loaded:</b> '
                'Showing sample findings from your personal home lab setup (~5 devices). '
                'Go to <b>Run Scan</b> to scan your real local devices.</div>',
                unsafe_allow_html=True,
            )

        kpis = get_personal_kpis(df)

        # Overview KPI row
        cols = st.columns(5)
        cols[0].markdown(kpi_card(kpis["total_devices"], "Total Devices", "default"), unsafe_allow_html=True)
        cols[1].markdown(kpi_card(kpis["open_findings"], "Open Findings", "warning" if kpis["open_findings"] > 0 else "success"), unsafe_allow_html=True)
        cols[2].markdown(kpi_card(kpis["critical_count"], "Critical", "danger" if kpis["critical_count"] > 0 else "default"), unsafe_allow_html=True)
        cols[3].markdown(kpi_card(kpis["high_count"], "High", "warning" if kpis["high_count"] > 0 else "default"), unsafe_allow_html=True)
        cols[4].markdown(kpi_card(kpis["fixed_count"], "Fixed / Resolved", "success"), unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Row: Severity Chart + What Changed
        col_chart, col_diff = st.columns([1.1, 1.4])

        with col_chart:
            st.markdown('<div class="section-header" style="font-size:1rem;">Severity Distribution</div>', unsafe_allow_html=True)
            # Personal mode severity breakdown
            is_open = ~df["status"].str.lower().isin(["fixed", "mitigated", "ignored", "accepted"])
            sev_df = df[is_open]["severity"].value_counts().reset_index()
            sev_df.columns = ["severity", "count"]

            if not sev_df.empty:
                fig_donut = px.pie(
                    sev_df,
                    names="severity",
                    values="count",
                    color="severity",
                    color_discrete_map=SEV_COLORS,
                    hole=0.55,
                )
                fig_donut.update_traces(textposition="outside", textinfo="percent+label")
                fig_donut = _plotly_layout(fig_donut)
                fig_donut.update_layout(showlegend=False, height=290)
                st.plotly_chart(fig_donut, use_container_width=True, key="personal_donut")
            else:
                st.info("No open findings to display.")

        with col_diff:
            st.markdown('<div class="section-header" style="font-size:1rem;">What Changed Since Last Scan</div>', unsafe_allow_html=True)
            diff = get_what_changed_summary(conn)
            if diff:
                st.markdown(
                    f"""
                    <div class="device-card">
                        <div style="font-weight:600; font-size:1.05rem; color:#e2e8f0; margin-bottom:8px;">
                            🎯 Last Scan Target: <span style="color:#6366f1;">{diff['target']}</span>
                        </div>
                        <div style="font-size:0.83rem; color:#94a3b8; margin-bottom:12px;">
                            <b>Timestamp:</b> {diff['scan_time']} &nbsp;|&nbsp; <b>Engine:</b> {diff['scanner']} &nbsp;|&nbsp; <b>Status:</b> {diff['status']}
                        </div>
                        <div style="display:flex; gap:16px;">
                            <div><span style="color:#ef4444; font-weight:700; font-size:1.4rem;">{diff['new_count']}</span> <span style="font-size:0.8rem; color:#94a3b8;">new</span></div>
                            <div><span style="color:#22c55e; font-weight:700; font-size:1.4rem;">{diff['fixed_count']}</span> <span style="font-size:0.8rem; color:#94a3b8;">fixed</span></div>
                            <div><span style="color:#6366f1; font-weight:700; font-size:1.4rem;">{diff['unchanged_count']}</span> <span style="font-size:0.8rem; color:#94a3b8;">unchanged</span></div>
                            <div><span style="color:#cbd5e1; font-weight:700; font-size:1.4rem;">{diff['findings_count']}</span> <span style="font-size:0.8rem; color:#94a3b8;">total on host</span></div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    """
                    <div class="device-card" style="text-align:center; padding:30px;">
                        <div style="font-size:1.5rem; margin-bottom:6px;">🔍</div>
                        <div style="font-weight:600; color:#cbd5e1;">No Live Scans Executed Yet</div>
                        <div style="font-size:0.82rem; color:#94a3b8; margin-top:4px;">
                            Execute a scan in <b>Run Scan</b> against your router, Raspberry Pi, or laptop to track changes automatically.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # Quick device overview summary table
        st.markdown('<div class="section-header" style="font-size:1rem;">Tracked Devices Summary</div>', unsafe_allow_html=True)
        devices = get_device_inventory(df, get_host_last_scanned(conn))
        if devices:
            dev_rows = []
            for d in devices:
                dev_rows.append({
                    "Device": d["asset"],
                    "Type": d["asset_type"],
                    "Open Findings": d["open_findings"],
                    "Critical": d["critical"],
                    "High": d["high"],
                    "Medium": d["medium"],
                    "Low": d["low"],
                    "Exposed Services": ", ".join(d["services"][:4]) + ("…" if len(d["services"]) > 4 else ""),
                })
            st.dataframe(pd.DataFrame(dev_rows), hide_index=True, use_container_width=True)

    # ────────────────────────────────────────────────────────
    # 2. DEVICES PAGE
    # ────────────────────────────────────────────────────────
    elif page == "💻 Devices":
        st.markdown('<div class="section-header">My Devices</div>', unsafe_allow_html=True)
        st.caption("Personal devices and home lab hardware tracked in your vulnerability register.")

        df = _load_df()
        if df.empty:
            st.info("No devices tracked yet. Add devices by running a scan or loading sample data.")
            st.stop()

        host_scan_df = get_host_last_scanned(conn)
        devices = get_device_inventory(df, host_scan_df)

        for dev in devices:
            with st.expander(
                f"💻 **{dev['asset']}** ({dev['asset_type']}) — {dev['open_findings']} open finding(s)"
                + (f" [🚨 {dev['critical']} Critical]" if dev['critical'] > 0 else "")
                + (f" [⚠️ {dev['high']} High]" if dev['high'] > 0 else ""),
                expanded=(dev['critical'] > 0),
            ):
                dcol1, dcol2, dcol3, dcol4 = st.columns(4)
                dcol1.markdown(f"**Device Type:** {dev['asset_type']}")
                dcol2.markdown(f"**Open Findings:** {dev['open_findings']}")
                dcol3.markdown(f"**Critical / High:** {dev['critical']} / {dev['high']}")
                dcol4.markdown(f"**Last Scanned:** {dev['last_scanned']}")

                if dev["services"]:
                    st.markdown(f"**Detected Services / Ports:** `{', '.join(dev['services'])}`")

                # Filter findings for this device
                dev_df = df[df["asset"] == dev["asset"]].copy()
                dev_df["status_norm"] = dev_df["status"].apply(lambda s: normalize_status(s, team_mode=False))
                cols_to_show = ["id", "vulnerability", "cve", "cvss", "severity", "service", "port", "status_norm", "notes"]
                st.dataframe(
                    dev_df[[c for c in cols_to_show if c in dev_df.columns]],
                    hide_index=True,
                    use_container_width=True,
                )

    # ────────────────────────────────────────────────────────
    # 3. FINDINGS PAGE
    # ────────────────────────────────────────────────────────
    elif page == "🔍 Findings":
        st.markdown('<div class="section-header">Findings</div>', unsafe_allow_html=True)
        st.caption("Search, filter, and track vulnerabilities across your devices.")

        df = _load_df()
        if df.empty:
            st.info("No findings loaded.")
            st.stop()

        # Map display status to personal mode (Open, Fixed, Ignored)
        df_display = df.copy()
        df_display["display_status"] = df_display["status"].apply(lambda s: normalize_status(s, team_mode=False))

        # Filters
        with st.expander("🔍 Filter & Search Findings", expanded=True):
            f1, f2, f3, f4 = st.columns(4)
            with f1:
                sev_filter = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=[])
            with f2:
                status_filter = st.multiselect("Status", ["Open", "Fixed", "Ignored"], default=[])
            with f3:
                device_filter = st.multiselect("Device", sorted(df_display["asset"].unique()), default=[])
            with f4:
                search_query = st.text_input("🔎 Search Description / CVE", placeholder="e.g. OpenSSL or port 22…")

        filtered = df_display.copy()
        if sev_filter:
            filtered = filtered[filtered["severity"].isin(sev_filter)]
        if status_filter:
            filtered = filtered[filtered["display_status"].isin(status_filter)]
        if device_filter:
            filtered = filtered[filtered["asset"].isin(device_filter)]
        if search_query:
            mask = (
                filtered["vulnerability"].str.contains(search_query, case=False, na=False)
                | filtered["cve"].str.contains(search_query, case=False, na=False)
                | filtered["asset"].str.contains(search_query, case=False, na=False)
                | filtered["service"].str.contains(search_query, case=False, na=False)
            )
            filtered = filtered[mask]

        st.caption(f"Showing **{len(filtered)}** of {len(df_display)} findings")

        # Table display (Personal mode: NO owner, NO SLA deadline, NO overdue, NO asset criticality)
        cols_personal = [
            "id", "asset", "vulnerability", "cve", "cvss",
            "severity", "service", "port", "display_status", "date_found", "notes",
        ]
        table_df = filtered[[c for c in cols_personal if c in filtered.columns]].copy()
        table_df.rename(columns={"asset": "Device", "display_status": "Status"}, inplace=True)

        st.dataframe(
            table_df,
            hide_index=True,
            use_container_width=True,
            height=380,
            column_config={
                "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
            },
        )

        # Inline Edit: Personal mode statuses (Open, Fixed, Ignored with note)
        st.markdown('<div class="section-header" style="font-size:1rem;">✏️ Update Finding Status</div>', unsafe_allow_html=True)
        if not filtered.empty:
            sel_id = st.selectbox("Select Finding ID", filtered["id"].tolist())
            row = df_display[df_display["id"] == sel_id].iloc[0]

            curr_status = row["display_status"]
            status_opts = ["Open", "Fixed", "Ignored"]
            idx = status_opts.index(curr_status) if curr_status in status_opts else 0

            ec1, ec2 = st.columns([1, 2])
            with ec1:
                new_status = st.selectbox("New Status", status_opts, index=idx)
            with ec2:
                notes_placeholder = "Reason for ignoring (required when ignored in personal mode)" if new_status == "Ignored" else "Notes (optional)"
                new_notes = st.text_input("Notes", value=str(row.get("notes", "")), placeholder=notes_placeholder)

            if st.button("💾 Save Update", key="btn_save_status"):
                if new_status == "Ignored" and not new_notes.strip():
                    st.warning("⚠️ Please provide a note explaining why this finding is ignored.")
                else:
                    update_finding(conn, int(sel_id), status=new_status, owner="me", notes=new_notes)
                    st.success(f"Finding #{sel_id} updated to {new_status}.")
                    st.rerun()

        # Export personal report
        st.markdown("---")
        st.markdown("#### 📤 Export Findings")
        exp_col1, exp_col2 = st.columns(2)
        with exp_col1:
            xl_data = export_excel(df, team_mode=False)
            st.download_button(
                "⬇️ Download Excel (.xlsx)",
                data=xl_data,
                file_name=f"vulnwatch_findings_{date.today().isoformat()}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key="dl_personal_xl",
            )
        with exp_col2:
            md_text = export_personal_findings_markdown(df)
            st.download_button(
                "⬇️ Download Markdown (.md)",
                data=md_text.encode("utf-8"),
                file_name=f"vulnwatch_summary_{date.today().isoformat()}.md",
                mime="text/markdown",
                key="dl_personal_md",
            )

    # ────────────────────────────────────────────────────────
    # 4. RUN SCAN PAGE
    # ────────────────────────────────────────────────────────
    elif page == "🎯 Run Scan":
        st.markdown('<div class="section-header">Run Scan</div>', unsafe_allow_html=True)

        st.markdown(
            """
            <div class="alert-box alert-danger">
                🔒 <b>Safety Restriction:</b> VulnWatch strictly limits scanning to RFC 1918 private subnets
                (<code>10.0.0.0/8</code>, <code>172.16.0.0/12</code>, <code>192.168.0.0/16</code>) and localhost (<code>127.0.0.1</code>).
                Public IP addresses and command injection characters are strictly rejected.
            </div>
            """,
            unsafe_allow_html=True,
        )

        tab_live, tab_import, tab_sample = st.tabs(["🚀 Live Network Scan", "📥 Import Scan File", "🎲 Sample Setup"])

        with tab_live:
            scanner = NmapScanner()
            is_avail, avail_msg = scanner.is_available()

            col_s1, col_s2 = st.columns([1.5, 1])
            with col_s1:
                if is_avail:
                    st.success(f"🟢 **Scanner Ready:** {avail_msg}")
                else:
                    st.warning(f"🟡 **Scanner Note:** {avail_msg}")
            with col_s2:
                st.info("💡 Scans run locally via safe subprocess array arguments (no shell injection).")

            st.markdown("### Scan My Device")
            sc_c1, sc_c2 = st.columns([2, 1])
            with sc_c1:
                target_ip = st.text_input(
                    "Target Device IP Address",
                    value="127.0.0.1",
                    help="Enter a private IP on your local network (e.g. 192.168.1.1, 10.0.0.5, 127.0.0.1).",
                )
                st.caption("💡 Quick targets: `127.0.0.1` (localhost), `10.12.178.238` (this PC on Wi-Fi), or enter your router/home server IP.")
            with sc_c2:
                device_type = st.selectbox(
                    "Device Type",
                    ["Laptop", "Raspberry Pi", "Home Server", "Router", "Virtual Machine", "Host"],
                    index=0,
                )

            if st.button("🚀 Start Scan", type="primary"):
                is_valid, err_msg, ip_obj = validate_scan_target(target_ip)
                if not is_valid:
                    st.error(f"❌ {err_msg}")
                elif not is_avail:
                    st.error(f"❌ Scanner unavailable: {avail_msg}")
                else:
                    with st.spinner(f"🔍 Scanning {target_ip} with Nmap (service detection & CVE correlation)…"):
                        try:
                            findings = scanner.scan(
                                target=str(ip_obj),
                                asset_criticality="Medium",
                                owner="me",
                                asset_type=device_type,
                            )
                            summary = reconcile_scan_results(
                                conn,
                                target=str(ip_obj),
                                scanned_findings=findings,
                                scanner_name=scanner.name,
                                user="Local User",
                            )
                            st.success(f"✅ Scan completed for {target_ip}!")
                            r1, r2, r3, r4 = st.columns(4)
                            r1.markdown(kpi_card(summary["new"], "New Findings", "danger" if summary["new"] > 0 else "default"), unsafe_allow_html=True)
                            r2.markdown(kpi_card(summary["unchanged"], "Unchanged", "default"), unsafe_allow_html=True)
                            r3.markdown(kpi_card(summary["mitigated"], "Fixed (Closed)", "success"), unsafe_allow_html=True)
                            r4.markdown(kpi_card(summary["total"], "Active on Device", "default"), unsafe_allow_html=True)

                            if findings:
                                st.markdown("#### 📋 Discovered Services & Findings on this Host")
                                rows = []
                                for f in findings:
                                    rows.append({
                                        "Port": f.port or "N/A",
                                        "Service": f.service,
                                        "Vulnerability / Exposure": f.vulnerability,
                                        "Severity": f.severity,
                                        "CVSS": f.cvss,
                                    })
                                st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
                            else:
                                st.info(f"ℹ️ **Scan completed for {target_ip}:** Host is reachable, but no listening services were detected on the top 100 ports.")
                        except Exception as ex:
                            st.error(f"❌ Scan execution failed: {ex}")

        with tab_import:
            st.markdown("#### Import from Nmap XML or CSV")
            st.caption("Upload results from an offline scan run on your machines.")

            up_nmap = st.file_uploader("Upload Nmap XML Output", type=["xml"], key="personal_nmap_up")
            if up_nmap and st.button("Import Nmap XML", key="btn_import_nmap"):
                try:
                    parsed = parse_nmap_xml(up_nmap.read())
                    insert_findings(conn, parsed)
                    st.success(f"✅ Imported {len(parsed)} findings from Nmap XML.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error parsing XML: {e}")

            st.markdown("---")
            up_csv = st.file_uploader("Upload Generic CSV Output", type=["csv"], key="personal_csv_up")
            if up_csv and st.button("Import CSV", key="btn_import_csv"):
                try:
                    parsed = parse_csv(up_csv.read())
                    insert_findings(conn, parsed)
                    st.success(f"✅ Imported {len(parsed)} findings from CSV.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error parsing CSV: {e}")

        with tab_sample:
            st.markdown("#### Sample Home Lab Setup")
            st.caption("Generate or reset personal sample data (~5 devices: Laptop, Pi, Server, Router, VM).")
            if st.button("🎲 Reset to Personal Sample Data"):
                clear_db(conn)
                findings = generate_demo_findings(25, seed=42, team_mode=False)
                insert_findings(conn, findings)
                st.success("✅ Sample home lab data loaded.")
                st.rerun()

    # ────────────────────────────────────────────────────────
    # 5. HISTORY PAGE
    # ────────────────────────────────────────────────────────
    elif page == "📜 History":
        st.markdown('<div class="section-header">Scan History</div>', unsafe_allow_html=True)
        st.caption("Audit log of past scan executions and reconciliation changes across your devices.")

        tab_scans, tab_cov = st.tabs(["📜 Scan Audit Log", "🖥️ Device Coverage"])

        with tab_scans:
            logs = get_scan_logs(conn)
            if logs.empty:
                st.info("No scan logs recorded yet. Run your first scan in **Run Scan**.")
            else:
                st.dataframe(logs, hide_index=True, use_container_width=True)

        with tab_cov:
            hosts = get_host_last_scanned(conn)
            if hosts.empty:
                st.info("No devices have been scanned yet.")
            else:
                st.dataframe(hosts, hide_index=True, use_container_width=True)


# ============================================================
# ============================================================
# TEAM MODE PAGES (when team_mode is ON)
# ============================================================
# ============================================================

else:

    # ────────────────────────────────────────────────────────
    # TEAM 1: EXECUTIVE SUMMARY
    # ────────────────────────────────────────────────────────
    if page == "📊 Executive Summary":
        st.markdown('<div class="section-header">Executive Summary</div>', unsafe_allow_html=True)
        df = _load_df()

        if df.empty:
            st.info("No findings. Load data via **Data Ingestion**.")
            st.stop()

        tkpis = get_team_kpis(df)

        cols = st.columns(6)
        metrics = [
            (tkpis["total"], "Total Findings", "default"),
            (tkpis["n_open"], "Open / In Progress", "warning"),
            (tkpis["n_critical"], "Critical", "danger"),
            (tkpis["n_high"], "High", "warning"),
            (tkpis["n_overdue"], "Overdue", "danger" if tkpis["n_overdue"] > 0 else "success"),
            (f"{tkpis['sla_pct']}%", "SLA Compliance", "success" if tkpis["sla_pct"] >= 80 else "danger"),
        ]
        for col, (val, label, variant) in zip(cols, metrics):
            col.markdown(kpi_card(val, label, variant), unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Charts: Donut + Top Assets
        col_left, col_right = st.columns([1, 1.6])

        with col_left:
            st.markdown('<div class="section-header" style="font-size:1rem;">Severity Distribution</div>', unsafe_allow_html=True)
            sev_counts = df["severity"].value_counts().reset_index()
            sev_counts.columns = ["severity", "count"]
            fig_donut = px.pie(
                sev_counts,
                names="severity",
                values="count",
                color="severity",
                color_discrete_map=SEV_COLORS,
                hole=0.6,
            )
            fig_donut.update_traces(textposition="outside", textinfo="percent+label")
            fig_donut = _plotly_layout(fig_donut)
            fig_donut.update_layout(showlegend=False, height=320)
            st.plotly_chart(fig_donut, use_container_width=True, key="donut_sev_team")

        with col_right:
            st.markdown('<div class="section-header" style="font-size:1rem;">Top 10 Riskiest Assets</div>', unsafe_allow_html=True)
            asset_risk = (
                df[df["status"].isin(["Open", "In Progress"])]
                .groupby("asset")["risk_score"]
                .sum()
                .nlargest(10)
                .reset_index()
                .sort_values("risk_score")
            )
            fig_bar = px.bar(
                asset_risk,
                x="risk_score",
                y="asset",
                orientation="h",
                color="risk_score",
                color_continuous_scale=["#22c55e", "#eab308", "#ea580c", "#dc2626"],
                labels={"risk_score": "Cumulative Risk Score", "asset": "Asset"},
            )
            fig_bar.update_coloraxes(showscale=False)
            fig_bar = _plotly_layout(fig_bar)
            fig_bar.update_layout(height=320, yaxis_title="")
            st.plotly_chart(fig_bar, use_container_width=True, key="top_assets_team")

        # Trend Chart
        st.markdown('<div class="section-header" style="font-size:1rem;">6-Month Trend: Opened vs Closed</div>', unsafe_allow_html=True)
        trend_df = get_trend_data(df)
        fig_trend = px.line(
            trend_df,
            x="year_month",
            y="Count",
            color="Type",
            markers=True,
            color_discrete_map={"Opened": "#ef4444", "Closed": "#22c55e"},
            labels={"year_month": "Month", "Count": "Findings"},
        )
        fig_trend.update_traces(line_width=2.5)
        fig_trend = _plotly_layout(fig_trend)
        fig_trend.update_layout(height=280)
        st.plotly_chart(fig_trend, use_container_width=True, key="trend_chart_team")

    # ────────────────────────────────────────────────────────
    # TEAM 2: RISK REGISTER
    # ────────────────────────────────────────────────────────
    elif page == "📋 Risk Register":
        st.markdown('<div class="section-header">Risk Register</div>', unsafe_allow_html=True)
        df = _load_df()

        if df.empty:
            st.info("No findings loaded.")
            st.stop()

        with st.expander("🔍 Filters & Search", expanded=True):
            fc1, fc2, fc3, fc4, fc5 = st.columns(5)
            with fc1:
                sev_filter = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=[])
            with fc2:
                status_filter = st.multiselect("Status", ["Open", "In Progress", "Mitigated", "Accepted"], default=[])
            with fc3:
                owner_filter = st.multiselect("Owner", sorted(df["owner"].dropna().unique()), default=[])
            with fc4:
                asset_filter = st.multiselect("Asset", sorted(df["asset"].unique()), default=[])
            with fc5:
                overdue_only = st.checkbox("Overdue Only", value=False)
            search = st.text_input("🔎 Search CVE / Vulnerability", placeholder="CVE-2021-44228 or log4j…")

        filtered = df.copy()
        if sev_filter:
            filtered = filtered[filtered["severity"].isin(sev_filter)]
        if status_filter:
            filtered = filtered[filtered["status"].isin(status_filter)]
        if owner_filter:
            filtered = filtered[filtered["owner"].isin(owner_filter)]
        if asset_filter:
            filtered = filtered[filtered["asset"].isin(asset_filter)]
        if overdue_only:
            filtered = filtered[filtered["overdue"] == 1]
        if search:
            mask = (
                filtered["cve"].str.contains(search, case=False, na=False)
                | filtered["vulnerability"].str.contains(search, case=False, na=False)
                | filtered["asset"].str.contains(search, case=False, na=False)
            )
            filtered = filtered[mask]

        st.caption(f"Showing **{len(filtered)}** of {len(df)} findings")

        display_cols = ["id", "asset", "asset_type", "asset_criticality", "cve", "cvss", "severity", "risk_score",
                        "owner", "status", "date_found", "target_date", "overdue"]
        display_df = filtered[[c for c in display_cols if c in filtered.columns]].copy()
        if "overdue" in display_df.columns:
            display_df["overdue"] = display_df["overdue"].map({1: "⚠️ Yes", 0: "No"})

        st.dataframe(
            display_df,
            use_container_width=True,
            height=400,
            hide_index=True,
            column_config={
                "risk_score": st.column_config.ProgressColumn(
                    "Risk Score", min_value=0, max_value=100, format="%.1f"
                ),
                "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
            },
        )

        st.markdown('<div class="section-header" style="font-size:1rem;">✏️ Edit Finding</div>', unsafe_allow_html=True)
        finding_ids = filtered["id"].tolist()
        if finding_ids:
            edit_id = st.selectbox("Select Finding ID to Edit", finding_ids)
            row = df[df["id"] == edit_id].iloc[0]

            ec1, ec2, ec3 = st.columns(3)
            with ec1:
                status_opts = ["Open", "In Progress", "Mitigated", "Accepted"]
                new_status = st.selectbox(
                    "Status",
                    status_opts,
                    index=status_opts.index(row["status"]) if row["status"] in status_opts else 0,
                )
            with ec2:
                new_owner = st.text_input("Owner", value=str(row.get("owner", "")))
            with ec3:
                new_notes = st.text_area("Notes", value=str(row.get("notes", "")), height=80)

            if st.button("💾 Save Changes", key="save_edit_team"):
                update_finding(conn, int(edit_id), new_status, new_owner, new_notes)
                st.success(f"Finding #{edit_id} updated.")
                st.rerun()

    # ────────────────────────────────────────────────────────
    # TEAM 3: REMEDIATION TRACKER
    # ────────────────────────────────────────────────────────
    elif page == "🔧 Remediation Tracker":
        st.markdown('<div class="section-header">Remediation Tracker</div>', unsafe_allow_html=True)
        df = _load_df()

        if df.empty:
            st.info("No findings loaded.")
            st.stop()

        today = date.today()
        week_end = today + timedelta(days=7)

        overdue_df = df[df["overdue"] == 1].copy()
        due_week_df = df[
            (df["overdue"] == 0)
            & df["status"].isin(["Open", "In Progress"])
            & (pd.to_datetime(df["target_date"]).dt.date <= week_end)
        ].copy()

        c1, c2, c3 = st.columns(3)
        c1.markdown(kpi_card(len(overdue_df), "Overdue Findings", "danger"), unsafe_allow_html=True)
        c2.markdown(kpi_card(len(due_week_df), "Due This Week", "warning"), unsafe_allow_html=True)
        open_total = len(df[df["status"].isin(["Open", "In Progress"])])
        c3.markdown(kpi_card(open_total, "Total Open", "default"), unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        tab1, tab2, tab3 = st.tabs(["🚨 Overdue", "📅 Due This Week", "👤 By Owner"])

        with tab1:
            if overdue_df.empty:
                st.markdown('<div class="alert-box alert-success">✅ No overdue findings!</div>', unsafe_allow_html=True)
            else:
                for owner, grp in overdue_df.sort_values("risk_score", ascending=False).groupby("owner"):
                    with st.expander(f"👤 {owner}  —  {len(grp)} overdue", expanded=True):
                        cols_show = ["id", "asset", "cve", "severity", "risk_score", "date_found", "target_date", "status"]
                        st.dataframe(grp[[c for c in cols_show if c in grp.columns]], hide_index=True, use_container_width=True)

        with tab2:
            if due_week_df.empty:
                st.markdown('<div class="alert-box alert-success">✅ Nothing due in the next 7 days.</div>', unsafe_allow_html=True)
            else:
                cols_show = ["id", "asset", "cve", "severity", "risk_score", "owner", "target_date", "status"]
                st.dataframe(due_week_df[[c for c in cols_show if c in due_week_df.columns]].sort_values("target_date"), hide_index=True, use_container_width=True)

        with tab3:
            open_by_owner = (
                df[df["status"].isin(["Open", "In Progress"])]
                .groupby("owner")
                .agg(
                    Total=("id", "count"),
                    Critical=("severity", lambda x: (x == "Critical").sum()),
                    High=("severity", lambda x: (x == "High").sum()),
                    Overdue=("overdue", "sum"),
                    Avg_Risk=("risk_score", "mean"),
                )
                .reset_index()
                .sort_values("Overdue", ascending=False)
            )
            open_by_owner["Avg_Risk"] = open_by_owner["Avg_Risk"].round(1)
            open_by_owner["Overdue"] = open_by_owner["Overdue"].astype(int)
            st.dataframe(open_by_owner, hide_index=True, use_container_width=True)

    # ────────────────────────────────────────────────────────
    # TEAM 4: COMPLIANCE VIEW
    # ────────────────────────────────────────────────────────
    elif page == "📐 Compliance View":
        st.markdown('<div class="section-header">Compliance Mapping</div>', unsafe_allow_html=True)
        st.caption("Mapped to NIST CSF and ISO 27001 Annex A controls.")

        df = _load_df()
        if df.empty:
            st.info("No findings loaded.")
            st.stop()

        tab_nist, tab_iso = st.tabs(["🏛️ NIST CSF", "📋 ISO 27001 Annex A"])

        with tab_nist:
            nist_info = {
                "Identify":  ("ID", "#6366f1", "Understand risks to systems, assets, data"),
                "Protect":   ("PR", "#22c55e", "Safeguards to limit cybersecurity impact"),
                "Detect":    ("DE", "#38bdf8", "Identify cybersecurity events"),
                "Respond":   ("RS", "#f59e0b", "Actions regarding detected incidents"),
                "Recover":   ("RC", "#a78bfa", "Restore impaired capabilities"),
            }
            nist_rows = []
            for _, r in df.iterrows():
                for f in str(r.get("nist_csf", "")).split(","):
                    f = f.strip()
                    if f:
                        nist_rows.append({"function": f, "severity": r["severity"], "risk_score": r["risk_score"]})
            nist_df = pd.DataFrame(nist_rows)

            cols = st.columns(5)
            for col, (func, (code, color, desc)) in zip(cols, nist_info.items()):
                count = len(nist_df[nist_df["function"] == func]) if not nist_df.empty else 0
                col.markdown(
                    f"""
                    <div class="kpi-card" style="border-color:{color}40;">
                        <div class="kpi-value" style="background:{color};-webkit-background-clip:text;background-clip:text;">{count}</div>
                        <div class="kpi-label">{func}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        with tab_iso:
            iso_counts = df["iso_control"].value_counts().reset_index()
            iso_counts.columns = ["Control", "Findings"]
            st.dataframe(iso_counts, hide_index=True, use_container_width=True)

    # ────────────────────────────────────────────────────────
    # TEAM 5: LIVE NETWORK SCAN
    # ────────────────────────────────────────────────────────
    elif page == "🎯 Live Network Scan":
        st.markdown('<div class="section-header">Live Network Scanning (Nmap)</div>', unsafe_allow_html=True)
        scanner = NmapScanner()
        is_avail, avail_msg = scanner.is_available()

        if is_avail:
            st.success(f"🟢 **Scanner Engine Ready:** {avail_msg}")
        else:
            st.warning(f"🟡 **Scanner Unavailable:** {avail_msg}")

        st.markdown("### ⚙️ Scan Configuration")
        c_target, c_crit, c_owner, c_type = st.columns([1.5, 1, 1, 1])
        with c_target:
            target_input = st.text_input("Target IPv4 Address", value="127.0.0.1")
        with c_crit:
            asset_crit = st.selectbox("Asset Criticality", ["High", "Medium", "Low"], index=1)
        with c_owner:
            owner_val = st.selectbox("Assigned Team", ["SecOps", "Network-Team", "WinAdmin-Team", "DevOps", "IT-Support", "Unassigned"], index=0)
        with c_type:
            asset_type_val = st.selectbox("Asset Type", ["Host", "Server-Linux", "Server-Windows", "Workstation", "Network"], index=0)

        if st.button("🚀 Launch Live Nmap Scan", type="primary"):
            is_valid, err_msg, ip_obj = validate_scan_target(target_input)
            if not is_valid:
                st.error(f"❌ {err_msg}")
            elif not is_avail:
                st.error(f"❌ Scanner unavailable: {avail_msg}")
            else:
                with st.spinner(f"🔍 Executing live scan on {target_input}…"):
                    try:
                        findings = scanner.scan(
                            target=str(ip_obj),
                            asset_criticality=asset_crit,
                            owner=owner_val,
                            asset_type=asset_type_val,
                        )
                        summary = reconcile_scan_results(
                            conn,
                            target=str(ip_obj),
                            scanned_findings=findings,
                            scanner_name=scanner.name,
                            user="Local User",
                        )
                        st.success(f"✅ Scan completed for {target_input}!")
                    except Exception as exc:
                        st.error(f"❌ Scan execution failed: {exc}")

    # ────────────────────────────────────────────────────────
    # TEAM 6: DATA INGESTION
    # ────────────────────────────────────────────────────────
    elif page == "📥 Data Ingestion":
        st.markdown('<div class="section-header">Data Ingestion</div>', unsafe_allow_html=True)
        tab_demo, tab_nmap, tab_csv = st.tabs(["🎲 Demo Mode", "🗺️ Nmap XML", "📄 CSV Import"])

        with tab_demo:
            n_findings = st.slider("Number of Findings", 20, 200, 50, 10)
            if st.button("🔄 Generate Demo Data"):
                clear_db(conn)
                findings = generate_demo_findings(n_findings, seed=42, team_mode=True)
                insert_findings(conn, findings)
                st.success(f"✅ Generated {len(findings)} demo findings.")
                st.rerun()

        with tab_nmap:
            nmap_file = st.file_uploader("Upload Nmap XML", type=["xml"], key="nmap_up_team")
            if nmap_file and st.button("🚀 Parse & Import", key="btn_nmap_team"):
                findings = parse_nmap_xml(nmap_file.read())
                insert_findings(conn, findings)
                st.success(f"✅ Imported {len(findings)} findings.")
                st.rerun()

        with tab_csv:
            csv_file = st.file_uploader("Upload CSV File", type=["csv"], key="csv_up_team")
            if csv_file and st.button("🚀 Parse & Import", key="btn_csv_team"):
                findings = parse_csv(csv_file.read())
                insert_findings(conn, findings)
                st.success(f"✅ Imported {len(findings)} findings.")
                st.rerun()

    # ────────────────────────────────────────────────────────
    # TEAM 7: EXPORT REPORTS
    # ────────────────────────────────────────────────────────
    elif page == "📤 Export Reports":
        st.markdown('<div class="section-header">Export Reports</div>', unsafe_allow_html=True)
        df = _load_df()

        if df.empty:
            st.info("No findings to export.")
            st.stop()

        col_xl, col_md = st.columns(2)
        with col_xl:
            st.markdown("### 📊 Excel Report")
            if st.button("📊 Generate Excel Report", key="gen_xl_team"):
                xl_bytes = export_excel(df, team_mode=True)
                st.download_button(
                    "⬇️ Download Excel (.xlsx)",
                    data=xl_bytes,
                    file_name=f"vulnwatch_team_report_{date.today().isoformat()}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    key="dl_xl_team",
                )

        with col_md:
            st.markdown("### 📝 Weekly Summary")
            if st.button("📝 Generate Weekly Summary", key="gen_md_team"):
                md_text = export_markdown_summary(df)
                st.download_button(
                    "⬇️ Download Markdown (.md)",
                    data=md_text.encode("utf-8"),
                    file_name=f"vulnwatch_summary_{date.today().isoformat()}.md",
                    mime="text/markdown",
                    key="dl_md_team",
                )
                st.markdown(md_text)
