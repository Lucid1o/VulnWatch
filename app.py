"""
app.py
======
Vulnerability & Risk Management Dashboard
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

from core.database import (
    get_connection,
    init_db,
    insert_findings,
    load_findings,
    refresh_overdue_flags,
    update_finding,
    clear_db,
)
from core.demo_data import generate_demo_findings
from core.exports import export_excel, export_markdown_summary
from core.parsers import parse_nmap_xml, parse_csv
from core.scoring import cvss_to_severity, compute_risk_score, sla_target_date, is_overdue

# ============================================================
# PAGE CONFIG (must be first Streamlit call)
# ============================================================
st.set_page_config(
    page_title="VulnTrack | Risk Dashboard",
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
/* ── Base ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Dark background */
.stApp {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #e2e8f0;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f172a 0%, #1a2744 100%);
    border-right: 1px solid rgba(99,102,241,0.2);
}
[data-testid="stSidebar"] * { color: #cbd5e1 !important; }
[data-testid="stSidebar"] .stRadio > label { color: #94a3b8 !important; font-size: 0.8rem; }

/* KPI Cards */
.kpi-card {
    background: linear-gradient(135deg, rgba(30,41,59,0.9) 0%, rgba(15,23,42,0.9) 100%);
    border: 1px solid rgba(99,102,241,0.3);
    border-radius: 12px;
    padding: 20px 24px;
    text-align: center;
    backdrop-filter: blur(10px);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.kpi-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(99,102,241,0.2);
}
.kpi-value {
    font-size: 2.2rem;
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
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94a3b8;
    margin-top: 6px;
}

/* Section headers */
.section-header {
    font-size: 1.4rem;
    font-weight: 700;
    color: #e2e8f0;
    border-left: 4px solid #6366f1;
    padding-left: 12px;
    margin: 28px 0 16px 0;
}

/* Severity badges */
.badge-critical { background:#dc2626; color:#fff; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600; }
.badge-high     { background:#ea580c; color:#fff; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600; }
.badge-medium   { background:#ca8a04; color:#fff; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600; }
.badge-low      { background:#16a34a; color:#fff; padding:2px 10px; border-radius:999px; font-size:0.78rem; font-weight:600; }

/* Streamlit overrides */
.stButton > button {
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 0.5rem 1.5rem;
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

/* DataFrames */
[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }

/* Info/warning boxes */
.alert-box {
    border-radius: 10px;
    padding: 14px 18px;
    margin: 10px 0;
    border-left: 4px solid;
}
.alert-danger  { background: rgba(220,38,38,0.12);  border-color: #dc2626; }
.alert-warning { background: rgba(234,179,8,0.12);  border-color: #eab308; }
.alert-info    { background: rgba(99,102,241,0.12); border-color: #6366f1; }
.alert-success { background: rgba(34,197,94,0.12);  border-color: #22c55e; }

/* Table styling */
.styled-table { width:100%; border-collapse:collapse; font-size:0.87rem; }
.styled-table th { background:#1e3a5f; color:#e2e8f0; padding:10px 14px; text-align:left; font-weight:600; }
.styled-table td { padding:9px 14px; border-bottom:1px solid rgba(99,102,241,0.1); color:#cbd5e1; }
.styled-table tr:hover td { background:rgba(99,102,241,0.08); }

/* Hide Streamlit branding */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 1.5rem; }

/* Logo / title */
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
# COLOUR MAPS (used for charts)
# ============================================================
SEV_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#eab308",
    "Low": "#22c55e",
    "Informational": "#64748b",
}
STATUS_COLORS = {
    "Open": "#dc2626",
    "In Progress": "#f59e0b",
    "Mitigated": "#22c55e",
    "Accepted": "#6366f1",
}

PLOTLY_THEME = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font_color="#cbd5e1",
    font_family="Inter",
)

# ============================================================
# DB INITIALISATION
# ============================================================

@st.cache_resource
def _get_conn() -> sqlite3.Connection:
    conn = get_connection()
    init_db(conn)
    return conn


conn = _get_conn()


def _load_df() -> pd.DataFrame:
    refresh_overdue_flags(conn)
    return load_findings(conn)


def _seed_demo_if_empty() -> None:
    df = load_findings(conn)
    if df.empty:
        with st.spinner("🔄 Loading demo data…"):
            findings = generate_demo_findings(150, seed=42)
            insert_findings(conn, findings)
        st.success("✅ Demo data loaded (150 findings across 15 hosts).")
        st.rerun()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown(
        """
        <div style="padding:8px 0 20px 0;">
            <div class="app-title">🛡️ VulnTrack</div>
            <div class="app-subtitle">Vulnerability & Risk Management</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    page = st.radio(
        "Navigation",
        [
            "📊 Executive Summary",
            "📋 Risk Register",
            "🔧 Remediation Tracker",
            "📐 Compliance View",
            "📥 Data Ingestion",
            "📤 Export Reports",
        ],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("#### 🗄️ Data Source")

    df_check = load_findings(conn)
    if df_check.empty:
        st.warning("No data loaded. Go to **Data Ingestion** or click below.")
        if st.button("Load Demo Data", key="sidebar_demo"):
            findings = generate_demo_findings(150, seed=42)
            insert_findings(conn, findings)
            st.rerun()
    else:
        st.success(f"✅ {len(df_check)} findings loaded")
        if st.button("🔄 Reset to Demo Data", key="sidebar_reset"):
            clear_db(conn)
            findings = generate_demo_findings(150, seed=42)
            insert_findings(conn, findings)
            st.rerun()

    st.markdown("---")
    st.markdown(
        "<div style='font-size:0.7rem;color:#475569;text-align:center;'>"
        "VulnTrack v1.0 · MIT License<br>Portfolio Project</div>",
        unsafe_allow_html=True,
    )


# ============================================================
# HELPERS
# ============================================================

def kpi_card(value: str | int | float, label: str, variant: str = "default") -> str:
    val_class = {"danger": "danger", "warning": "warning", "success": "success"}.get(variant, "")
    return f"""
    <div class="kpi-card">
        <div class="kpi-value {val_class}">{value}</div>
        <div class="kpi-label">{label}</div>
    </div>
    """


def severity_badge(severity: str) -> str:
    cls = f"badge-{severity.lower()}"
    return f'<span class="{cls}">{severity}</span>'


def _plotly_layout(fig: go.Figure, title: str = "") -> go.Figure:
    fig.update_layout(
        title=title,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#cbd5e1", family="Inter"),
        margin=dict(l=10, r=10, t=40, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)", font_color="#94a3b8"),
    )
    fig.update_xaxes(gridcolor="rgba(99,102,241,0.1)", zerolinecolor="rgba(0,0,0,0)")
    fig.update_yaxes(gridcolor="rgba(99,102,241,0.1)", zerolinecolor="rgba(0,0,0,0)")
    return fig


# ============================================================
# AUTO SEED DEMO
# ============================================================
_seed_demo_if_empty()

# ============================================================
# PAGE: EXECUTIVE SUMMARY
# ============================================================
if page == "📊 Executive Summary":
    st.markdown('<div class="section-header">Executive Summary</div>', unsafe_allow_html=True)

    df = _load_df()

    if df.empty:
        st.info("No findings. Load data via **Data Ingestion**.")
        st.stop()

    # ── KPIs ────────────────────────────────────────────────
    open_df = df[df["status"].isin(["Open", "In Progress"])]
    total = len(df)
    n_open = len(open_df)
    n_critical = len(df[df["severity"] == "Critical"])
    n_overdue = int(df["overdue"].sum())
    n_high = len(df[df["severity"] == "High"])

    active = df[df["status"].isin(["Open", "In Progress", "Mitigated", "Accepted"])]
    n_on_time = len(active[active["overdue"] == 0])
    sla_pct = round(n_on_time / len(active) * 100, 1) if len(active) else 100.0

    # Mean time to remediate (mitigated items)
    mit_df = df[df["status"] == "Mitigated"].copy()
    if not mit_df.empty:
        mit_df["date_found_dt"] = pd.to_datetime(mit_df["date_found"])
        mit_df["target_dt"]     = pd.to_datetime(mit_df["target_date"])
        mttr = round((mit_df["target_dt"] - mit_df["date_found_dt"]).dt.days.mean(), 1)
    else:
        mttr = "N/A"

    cols = st.columns(6)
    metrics = [
        (total,      "Total Findings",    "default"),
        (n_open,     "Open / In Progress","warning"),
        (n_critical, "Critical",          "danger"),
        (n_high,     "High",              "warning"),
        (n_overdue,  "Overdue",           "danger" if n_overdue > 0 else "success"),
        (f"{sla_pct}%", "SLA Compliance", "success" if sla_pct >= 80 else "danger"),
    ]
    for col, (val, label, variant) in zip(cols, metrics):
        col.markdown(kpi_card(val, label, variant), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Row 1: Donut + Top assets ────────────────────────────
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
        st.plotly_chart(fig_donut, use_container_width=True, key="donut_sev")

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
        st.plotly_chart(fig_bar, use_container_width=True, key="top_assets")

    # ── Row 2: 6-month trend ─────────────────────────────────
    st.markdown('<div class="section-header" style="font-size:1rem;">6-Month Trend: Opened vs Closed</div>', unsafe_allow_html=True)

    df["date_found_dt"] = pd.to_datetime(df["date_found"])
    df["year_month"] = df["date_found_dt"].dt.to_period("M").astype(str)

    opened = df.groupby("year_month").size().reset_index(name="Opened")
    closed = (
        df[df["status"].isin(["Mitigated", "Accepted"])]
        .groupby("year_month")
        .size()
        .reset_index(name="Closed")
    )
    trend = opened.merge(closed, on="year_month", how="outer").fillna(0).sort_values("year_month")
    trend_melted = trend.melt("year_month", var_name="Type", value_name="Count")

    fig_trend = px.line(
        trend_melted,
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
    st.plotly_chart(fig_trend, use_container_width=True, key="trend_chart")

    # ── Row 3: Status breakdown + MTTR ──────────────────────
    col_a, col_b, col_c = st.columns([1, 1, 1])

    with col_a:
        st.markdown('<div class="section-header" style="font-size:1rem;">Status Breakdown</div>', unsafe_allow_html=True)
        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["status", "count"]
        fig_status = px.bar(
            status_counts,
            x="status",
            y="count",
            color="status",
            color_discrete_map=STATUS_COLORS,
            labels={"count": "Count", "status": ""},
        )
        fig_status = _plotly_layout(fig_status)
        fig_status.update_layout(height=250, showlegend=False)
        st.plotly_chart(fig_status, use_container_width=True, key="status_bar")

    with col_b:
        st.markdown('<div class="section-header" style="font-size:1rem;">Asset Type Risk Share</div>', unsafe_allow_html=True)
        type_risk = df.groupby("asset_type")["risk_score"].sum().reset_index()
        fig_type = px.pie(
            type_risk,
            names="asset_type",
            values="risk_score",
            color_discrete_sequence=["#6366f1", "#8b5cf6", "#38bdf8", "#f59e0b"],
            hole=0.5,
        )
        fig_type = _plotly_layout(fig_type)
        fig_type.update_layout(height=250, showlegend=True)
        st.plotly_chart(fig_type, use_container_width=True, key="type_risk")

    with col_c:
        st.markdown('<div class="section-header" style="font-size:1rem;">Quick Stats</div>', unsafe_allow_html=True)
        stats_data = {
            "Metric": ["Avg CVSS", "Avg Risk Score", "Mean Time to Remediate", "Accepted Risk", "Unique Hosts"],
            "Value": [
                f"{df['cvss'].mean():.1f}",
                f"{df['risk_score'].mean():.1f}",
                f"{mttr} days" if isinstance(mttr, float) else mttr,
                str(len(df[df["status"] == "Accepted"])),
                str(df["asset"].nunique()),
            ],
        }
        st.dataframe(
            pd.DataFrame(stats_data),
            hide_index=True,
            use_container_width=True,
            height=200,
        )


# ============================================================
# PAGE: RISK REGISTER
# ============================================================
elif page == "📋 Risk Register":
    st.markdown('<div class="section-header">Risk Register</div>', unsafe_allow_html=True)
    df = _load_df()

    if df.empty:
        st.info("No findings loaded.")
        st.stop()

    # ── Filters ─────────────────────────────────────────────
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

    # ── Display table ────────────────────────────────────────
    display_cols = ["id", "asset", "asset_type", "cve", "cvss", "severity", "risk_score",
                    "owner", "status", "date_found", "target_date", "overdue"]
    display_df = filtered[[c for c in display_cols if c in filtered.columns]].copy()
    display_df["overdue"] = display_df["overdue"].map({1: "⚠️ Yes", 0: "No"})

    st.dataframe(
        display_df,
        use_container_width=True,
        height=400,
        hide_index=True,
        column_config={
            "id": st.column_config.NumberColumn("ID", width="small"),
            "risk_score": st.column_config.ProgressColumn(
                "Risk Score", min_value=0, max_value=100, format="%.1f"
            ),
            "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
        },
    )

    # ── Inline Edit ─────────────────────────────────────────
    st.markdown('<div class="section-header" style="font-size:1rem;">✏️ Edit Finding</div>', unsafe_allow_html=True)
    finding_ids = filtered["id"].tolist()
    if not finding_ids:
        st.info("No findings match the current filter.")
    else:
        edit_id = st.selectbox("Select Finding ID to Edit", finding_ids)
        row = df[df["id"] == edit_id].iloc[0]

        ec1, ec2, ec3 = st.columns(3)
        with ec1:
            new_status = st.selectbox(
                "Status",
                ["Open", "In Progress", "Mitigated", "Accepted"],
                index=["Open", "In Progress", "Mitigated", "Accepted"].index(row["status"])
                if row["status"] in ["Open", "In Progress", "Mitigated", "Accepted"] else 0,
            )
        with ec2:
            new_owner = st.text_input("Owner", value=str(row.get("owner", "")))
        with ec3:
            new_notes = st.text_area("Notes", value=str(row.get("notes", "")), height=80)

        if st.button("💾 Save Changes", key="save_edit"):
            update_finding(conn, int(edit_id), new_status, new_owner, new_notes)
            st.success(f"Finding #{edit_id} updated.")
            st.rerun()

        st.markdown(
            f"""
            <div class="alert-box alert-info" style="margin-top:10px;">
            <b>Selected:</b> [{row.get('cve','')}] {row.get('vulnerability','')} on <b>{row.get('asset','')}</b>
            &nbsp;|&nbsp; CVSS: <b>{row.get('cvss','')}</b>
            &nbsp;|&nbsp; Severity: <b>{row.get('severity','')}</b>
            &nbsp;|&nbsp; Risk Score: <b>{row.get('risk_score','')}</b>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================
# PAGE: REMEDIATION TRACKER
# ============================================================
elif page == "🔧 Remediation Tracker":
    st.markdown('<div class="section-header">Remediation Tracker</div>', unsafe_allow_html=True)
    df = _load_df()

    if df.empty:
        st.info("No findings loaded.")
        st.stop()

    today = date.today()
    week_end = today + timedelta(days=7)

    overdue_df   = df[df["overdue"] == 1].copy()
    due_week_df  = df[
        (df["overdue"] == 0)
        & df["status"].isin(["Open", "In Progress"])
        & (pd.to_datetime(df["target_date"]).dt.date <= week_end)
    ].copy()

    # ── Summary cards ────────────────────────────────────────
    c1, c2, c3 = st.columns(3)
    c1.markdown(kpi_card(len(overdue_df), "Overdue Findings", "danger"), unsafe_allow_html=True)
    c2.markdown(kpi_card(len(due_week_df), "Due This Week", "warning"), unsafe_allow_html=True)
    open_total = len(df[df["status"].isin(["Open", "In Progress"])])
    c3.markdown(kpi_card(open_total, "Total Open", "default"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["🚨 Overdue", "📅 Due This Week", "👤 By Owner"])

    # ── Tab 1: Overdue ───────────────────────────────────────
    with tab1:
        if overdue_df.empty:
            st.markdown(
                '<div class="alert-box alert-success">✅ No overdue findings!</div>',
                unsafe_allow_html=True,
            )
        else:
            for owner, grp in overdue_df.sort_values("risk_score", ascending=False).groupby("owner"):
                with st.expander(f"👤 {owner}  —  {len(grp)} overdue", expanded=True):
                    cols_show = ["id", "asset", "cve", "severity", "risk_score", "date_found", "target_date", "status"]
                    st.dataframe(
                        grp[[c for c in cols_show if c in grp.columns]],
                        hide_index=True,
                        use_container_width=True,
                        column_config={
                            "risk_score": st.column_config.ProgressColumn(
                                "Risk", min_value=0, max_value=100, format="%.1f"
                            )
                        },
                    )

    # ── Tab 2: Due this week ─────────────────────────────────
    with tab2:
        if due_week_df.empty:
            st.markdown(
                '<div class="alert-box alert-success">✅ Nothing due in the next 7 days.</div>',
                unsafe_allow_html=True,
            )
        else:
            cols_show = ["id", "asset", "cve", "severity", "risk_score", "owner", "target_date", "status"]
            st.dataframe(
                due_week_df[[c for c in cols_show if c in due_week_df.columns]].sort_values("target_date"),
                hide_index=True,
                use_container_width=True,
                column_config={
                    "risk_score": st.column_config.ProgressColumn(
                        "Risk", min_value=0, max_value=100, format="%.1f"
                    )
                },
            )

    # ── Tab 3: By Owner ──────────────────────────────────────
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

        fig_owner = px.bar(
            open_by_owner,
            x="owner",
            y="Total",
            color="Critical",
            color_continuous_scale=["#6366f1", "#dc2626"],
            labels={"owner": "Owner", "Total": "Open Findings", "Critical": "Critical"},
            title="Open Findings by Owner",
        )
        fig_owner = _plotly_layout(fig_owner, "Open Findings by Owner")
        fig_owner.update_layout(height=300, xaxis_tickangle=-30)
        st.plotly_chart(fig_owner, use_container_width=True, key="owner_bar")


# ============================================================
# PAGE: COMPLIANCE VIEW
# ============================================================
elif page == "📐 Compliance View":
    st.markdown('<div class="section-header">Compliance Mapping</div>', unsafe_allow_html=True)
    st.caption(
        "Findings are mapped to **NIST CSF** functions and **ISO/IEC 27001:2022 Annex A** controls. "
        "This view helps track control coverage and gaps."
    )
    df = _load_df()

    if df.empty:
        st.info("No findings loaded.")
        st.stop()

    tab_nist, tab_iso = st.tabs(["🏛️ NIST CSF", "📋 ISO 27001 Annex A"])

    # ── NIST CSF ─────────────────────────────────────────────
    with tab_nist:
        nist_info = {
            "Identify":  ("ID", "#6366f1", "Understand risks to systems, people, assets, data"),
            "Protect":   ("PR", "#22c55e", "Safeguards to limit impact of cybersecurity events"),
            "Detect":    ("DE", "#38bdf8", "Identify cybersecurity events"),
            "Respond":   ("RS", "#f59e0b", "Actions regarding detected cybersecurity incidents"),
            "Recover":   ("RC", "#a78bfa", "Restore capabilities impaired by incidents"),
        }

        # Expand comma-separated nist_csf to one row per function
        nist_rows = []
        for _, row in df.iterrows():
            funcs = str(row.get("nist_csf", "")).split(",")
            for f in funcs:
                f = f.strip()
                if f:
                    nist_rows.append({
                        "function": f,
                        "severity": row["severity"],
                        "risk_score": row["risk_score"],
                        "status": row["status"],
                        "asset": row["asset"],
                        "cve": row["cve"],
                    })
        nist_df = pd.DataFrame(nist_rows)

        # KPI cards per function
        cols = st.columns(5)
        for col, (func, (code, color, desc)) in zip(cols, nist_info.items()):
            count = len(nist_df[nist_df["function"] == func]) if not nist_df.empty else 0
            col.markdown(
                f"""
                <div class="kpi-card" style="border-color:{color}40;">
                    <div class="kpi-value" style="background:{color};-webkit-background-clip:text;background-clip:text;">{count}</div>
                    <div class="kpi-label">{func}</div>
                    <div style="font-size:0.68rem;color:#64748b;margin-top:4px;">{desc[:38]}…</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)

        if not nist_df.empty:
            # Heatmap: function vs severity
            pivot = nist_df.groupby(["function", "severity"]).size().unstack(fill_value=0)
            # Ensure all severity columns exist
            for s in ["Critical", "High", "Medium", "Low"]:
                if s not in pivot.columns:
                    pivot[s] = 0
            pivot = pivot[["Critical", "High", "Medium", "Low"]]

            fig_heat = px.imshow(
                pivot,
                color_continuous_scale=["#0f172a", "#6366f1", "#ef4444"],
                text_auto=True,
                labels=dict(x="Severity", y="NIST Function", color="Count"),
                title="Findings Count: NIST CSF Function × Severity",
            )
            fig_heat = _plotly_layout(fig_heat)
            fig_heat.update_layout(height=350)
            st.plotly_chart(fig_heat, use_container_width=True, key="nist_heat")

            st.markdown("#### Detailed Mapping")
            st.dataframe(
                nist_df.sort_values("risk_score", ascending=False).head(50),
                hide_index=True,
                use_container_width=True,
            )

    # ── ISO 27001 ────────────────────────────────────────────
    with tab_iso:
        iso_descriptions = {
            "A.8.8":  "Management of technical vulnerabilities",
            "A.9.2":  "User access management",
            "A.9.4":  "System and application access control",
            "A.10.1": "Cryptographic controls",
            "A.12.6": "Technical vulnerability management",
            "A.13.1": "Network security management",
            "A.14.2": "Security in development and support processes",
            "A.16.1": "Management of information security incidents",
        }

        iso_counts = df["iso_control"].value_counts().reset_index()
        iso_counts.columns = ["Control", "Findings"]
        iso_counts["Description"] = iso_counts["Control"].map(iso_descriptions).fillna("Other control")

        # Coverage gauge: % of our known controls touched
        covered = len(set(df["iso_control"].dropna()) & set(iso_descriptions.keys()))
        total_controls = len(iso_descriptions)
        coverage_pct = round(covered / total_controls * 100)

        cc1, cc2 = st.columns([1, 2])
        with cc1:
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=coverage_pct,
                number={"suffix": "%", "font": {"color": "#6366f1", "size": 40}},
                title={"text": "Control Coverage", "font": {"color": "#cbd5e1"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#64748b"},
                    "bar": {"color": "#6366f1"},
                    "bgcolor": "rgba(0,0,0,0)",
                    "steps": [
                        {"range": [0, 40],  "color": "rgba(220,38,38,0.2)"},
                        {"range": [40, 70], "color": "rgba(234,179,8,0.2)"},
                        {"range": [70, 100],"color": "rgba(34,197,94,0.2)"},
                    ],
                    "threshold": {"line": {"color": "#ef4444", "width": 3}, "value": 80},
                },
            ))
            fig_gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#cbd5e1",
                height=250,
                margin=dict(l=20, r=20, t=40, b=0),
            )
            st.plotly_chart(fig_gauge, use_container_width=True, key="iso_gauge")

        with cc2:
            fig_iso = px.bar(
                iso_counts,
                x="Control",
                y="Findings",
                color="Findings",
                color_continuous_scale=["#22c55e", "#eab308", "#dc2626"],
                text="Findings",
                hover_data=["Description"],
                title="Findings by ISO 27001 Control",
            )
            fig_iso.update_traces(textposition="outside")
            fig_iso.update_coloraxes(showscale=False)
            fig_iso = _plotly_layout(fig_iso)
            fig_iso.update_layout(height=250)
            st.plotly_chart(fig_iso, use_container_width=True, key="iso_bar")

        st.markdown("#### Control Details")
        iso_table = iso_counts.copy()
        iso_table["% of Total"] = (iso_table["Findings"] / len(df) * 100).round(1).astype(str) + "%"
        st.dataframe(iso_table, hide_index=True, use_container_width=True)


# ============================================================
# PAGE: DATA INGESTION
# ============================================================
elif page == "📥 Data Ingestion":
    st.markdown('<div class="section-header">Data Ingestion</div>', unsafe_allow_html=True)

    tab_demo, tab_nmap, tab_csv = st.tabs(["🎲 Demo Mode", "🗺️ Nmap XML", "📄 CSV Import"])

    # ── Demo Mode ────────────────────────────────────────────
    with tab_demo:
        st.markdown(
            """
            <div class="alert-box alert-info">
            Auto-generates <b>~150 realistic findings</b> across 15 hosts using real CVE IDs,
            CVSS scores, and dates spread over the past 6 months. Use this to explore the dashboard.
            </div>
            """,
            unsafe_allow_html=True,
        )
        seed = st.number_input("Random Seed (for reproducibility)", value=42, min_value=0)
        n_findings = st.slider("Number of Findings", 50, 300, 150, 10)

        if st.button("🔄 Generate Demo Data"):
            clear_db(conn)
            with st.spinner("Generating findings…"):
                findings = generate_demo_findings(n_findings, seed=int(seed))
                insert_findings(conn, findings)
            st.success(f"✅ Generated {len(findings)} demo findings.")
            st.rerun()

    # ── Nmap XML ─────────────────────────────────────────────
    with tab_nmap:
        st.markdown(
            """
            <div class="alert-box alert-info">
            Upload an Nmap scan run with <code>nmap -sV -oX output.xml &lt;target&gt;</code>.
            Each open port with a detected service becomes a finding. CVSS is estimated via
            port/service heuristics.
            </div>
            """,
            unsafe_allow_html=True,
        )
        nmap_file = st.file_uploader("Upload Nmap XML", type=["xml"], key="nmap_upload")
        replace_nmap = st.checkbox("Replace existing data", value=False, key="nmap_replace")
        if nmap_file and st.button("🚀 Parse & Import", key="nmap_import"):
            try:
                findings = parse_nmap_xml(nmap_file.read())
                if replace_nmap:
                    clear_db(conn)
                insert_findings(conn, findings)
                st.success(f"✅ Imported {len(findings)} findings from Nmap XML.")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Error parsing Nmap XML: {e}")

    # ── CSV Import ───────────────────────────────────────────
    with tab_csv:
        st.markdown(
            """
            <div class="alert-box alert-info">
            Upload a CSV export from any scanner. Required columns: <code>asset</code>, <code>vulnerability</code>.
            Optional: <code>cve</code>, <code>cvss</code>, <code>severity</code>, <code>service</code>,
            <code>port</code>, <code>owner</code>, <code>status</code>, <code>asset_criticality</code>.
            Common aliases (host, description, score, ip) are auto-resolved.
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.download_button(
            "⬇️ Download Sample CSV Template",
            data=(
                "asset,vulnerability,cve,cvss,service,port,owner,status,asset_criticality,asset_type,notes\n"
                "web-server-01,Apache Log4Shell RCE,CVE-2021-44228,10.0,apache/2.14.1,443,alice@corp,Open,High,Server-Linux,\n"
                "win-dc-01,PrintNightmare RCE,CVE-2021-34527,9.8,spoolsv,445,bob@corp,In Progress,High,Server-Windows,\n"
            ),
            file_name="vuln_template.csv",
            mime="text/csv",
        )

        csv_file = st.file_uploader("Upload CSV File", type=["csv"], key="csv_upload")
        replace_csv = st.checkbox("Replace existing data", value=False, key="csv_replace")
        if csv_file and st.button("🚀 Parse & Import", key="csv_import"):
            try:
                findings = parse_csv(csv_file.read())
                if replace_csv:
                    clear_db(conn)
                insert_findings(conn, findings)
                st.success(f"✅ Imported {len(findings)} findings from CSV.")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Error parsing CSV: {e}")

        # PowerShell note
        st.markdown("---")
        st.markdown(
            """
            **🖥️ Windows Host Collection**  
            Run `scripts/collect_windows_info.ps1` (PowerShell, run as Administrator) to collect
            local users, open ports, and installed hotfixes. The script outputs a CSV you can
            import here.
            ```powershell
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
            .\\scripts\\collect_windows_info.ps1 -OutputPath .\\scan_output.csv
            ```
            """
        )


# ============================================================
# PAGE: EXPORT REPORTS
# ============================================================
elif page == "📤 Export Reports":
    st.markdown('<div class="section-header">Export Reports</div>', unsafe_allow_html=True)
    df = _load_df()

    if df.empty:
        st.info("No findings to export. Load data first.")
        st.stop()

    col_xl, col_md = st.columns(2)

    with col_xl:
        st.markdown(
            """
            ### 📊 Excel Report
            Multi-sheet workbook with:
            - **Summary** – KPI table
            - **Register** – Full risk register (colour-coded severity)
            - **Overdue** – Overdue findings only
            - **Charts** – Severity distribution chart
            """
        )
        if st.button("📊 Generate Excel Report", key="gen_excel"):
            with st.spinner("Building workbook…"):
                xl_bytes = export_excel(df)
            today_str = date.today().isoformat()
            st.download_button(
                "⬇️ Download Excel (.xlsx)",
                data=xl_bytes,
                file_name=f"vuln_report_{today_str}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key="dl_excel",
            )

    with col_md:
        st.markdown(
            """
            ### 📝 Management Summary
            Markdown weekly report with:
            - Executive KPI overview
            - Top 5 highest-risk open findings
            - Overdue findings grouped by owner
            - Remediation progress table
            - Recommended actions
            """
        )
        if st.button("📝 Generate Management Summary", key="gen_md"):
            md_text = export_markdown_summary(df)
            today_str = date.today().isoformat()
            st.download_button(
                "⬇️ Download Markdown (.md)",
                data=md_text.encode("utf-8"),
                file_name=f"mgmt_summary_{today_str}.md",
                mime="text/markdown",
                key="dl_md",
            )
            st.markdown("#### Preview")
            st.markdown(md_text)

    st.markdown("---")
    st.markdown(
        """
        <div class="alert-box alert-info">
        💡 <b>Tip:</b> Open the Markdown file in any Markdown editor or convert to PDF with
        <code>pandoc mgmt_summary.md -o report.pdf</code> (requires Pandoc).
        </div>
        """,
        unsafe_allow_html=True,
    )
