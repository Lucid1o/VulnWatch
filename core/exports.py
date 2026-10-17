"""
core/exports.py
===============
Reporting: Excel workbook and Markdown summary for VulnWatch.
"""

from __future__ import annotations

import io
from datetime import date, datetime
from typing import Any

import pandas as pd

# ---------------------------------------------------------------------------
# Excel Export
# ---------------------------------------------------------------------------

_SEV_FILLS = {
    "Critical": "FFDC2626",
    "High":     "FFEA580C",
    "Medium":   "FFEAB308",
    "Low":      "FF22C55E",
}


def export_excel(df: pd.DataFrame, team_mode: bool = True) -> bytes:
    """
    Build a multi-sheet Excel workbook and return raw bytes.

    Sheets
    ------
    Summary   – KPI table
    Register  – Full findings register with colour coding
    Overdue   – Filtered overdue findings (in Team Mode) or Active (Personal)
    Charts    – Severity distribution data table
    """
    buf = io.BytesIO()
    today = date.today().isoformat()

    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        wb = writer.book

        from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
        from openpyxl.utils import get_column_letter

        thin = Side(style="thin", color="FFCCCCCC")
        border = Border(left=thin, right=thin, top=thin, bottom=thin)
        header_font = Font(name="Calibri", bold=True, color="FFFFFFFF", size=11)
        header_fill = PatternFill("solid", fgColor="FF1E3A5F")

        def style_header(ws, row: int, ncols: int):
            for col in range(1, ncols + 1):
                cell = ws.cell(row=row, column=col)
                cell.font = header_font
                cell.fill = header_fill
                cell.alignment = Alignment(horizontal="center", vertical="center")
                cell.border = border

        def auto_width(ws):
            for col in ws.columns:
                max_len = max((len(str(c.value or "")) for c in col), default=10)
                ws.column_dimensions[get_column_letter(col[0].column)].width = min(max_len + 4, 50)

        # ---- Summary Sheet -------------------------------------------------
        ws_sum = wb.create_sheet("Summary")
        ws_sum.sheet_view.showGridLines = False

        title_font = Font(name="Calibri", bold=True, size=16, color="FF1E3A5F")
        ws_sum["A1"] = "VulnWatch – Vulnerability & Risk Summary"
        ws_sum["A1"].font = title_font
        ws_sum["A2"] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        ws_sum["A2"].font = Font(italic=True, color="FF666666")
        ws_sum.merge_cells("A1:D1")

        kpis = [
            ("Total Findings",          len(df)),
            ("Open",                    len(df[~df["status"].str.lower().isin(["mitigated", "accepted", "fixed", "ignored"])])),
            ("Critical",                len(df[df["severity"] == "Critical"])),
            ("High",                    len(df[df["severity"] == "High"])),
            ("Overdue",                 int(df["overdue"].sum()) if "overdue" in df.columns else 0),
            ("Mitigated / Fixed",       len(df[df["status"].str.lower().isin(["mitigated", "fixed"])])),
            ("Avg Risk Score",          round(df["risk_score"].mean(), 1) if len(df) and "risk_score" in df.columns else 0),
            ("Report Date",             today),
        ]
        ws_sum.append([])
        ws_sum.append(["Metric", "Value"])
        style_header(ws_sum, ws_sum.max_row, 2)
        for label, val in kpis:
            ws_sum.append([label, val])
        auto_width(ws_sum)

        # ---- Register Sheet ------------------------------------------------
        if not team_mode:
            register_cols = ["id", "asset", "asset_type", "vulnerability", "cve", "cvss",
                             "severity", "service", "port", "status", "date_found", "notes"]
        else:
            register_cols = ["id", "asset", "asset_type", "asset_criticality", "vulnerability",
                             "cve", "cvss", "severity", "risk_score", "service", "port",
                             "owner", "status", "date_found", "target_date", "overdue", "notes"]

        available_cols = [c for c in register_cols if c in df.columns]
        df_reg = df[available_cols].copy()
        df_reg.to_excel(writer, sheet_name="Register", index=False)
        ws_reg = wb["Register"]
        style_header(ws_reg, 1, len(available_cols))

        sev_col_idx = available_cols.index("severity") + 1 if "severity" in available_cols else None
        if sev_col_idx:
            for row_idx in range(2, len(df_reg) + 2):
                cell = ws_reg.cell(row=row_idx, column=sev_col_idx)
                fill_color = _SEV_FILLS.get(cell.value)
                if fill_color:
                    cell.fill = PatternFill("solid", fgColor=fill_color)
                    cell.font = Font(name="Calibri", color="FFFFFFFF", bold=True)
        auto_width(ws_reg)

        # ---- Overdue Sheet -------------------------------------------------
        if "overdue" in df.columns and int(df["overdue"].sum()) > 0:
            df_overdue = df[df["overdue"] == 1][available_cols].copy()
        else:
            # Empty frame with same columns
            df_overdue = pd.DataFrame(columns=available_cols)
        df_overdue.to_excel(writer, sheet_name="Overdue", index=False)
        ws_overdue = wb["Overdue"]
        style_header(ws_overdue, 1, len(available_cols))
        auto_width(ws_overdue)

        # ---- Charts Sheet (data table) -------------------------------------
        sev_counts = df["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        sev_counts.to_excel(writer, sheet_name="Charts", index=False)
        ws_charts = wb["Charts"]
        style_header(ws_charts, 1, 2)
        auto_width(ws_charts)

        if "Sheet" in wb.sheetnames:
            del wb["Sheet"]

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Markdown Report Export
# ---------------------------------------------------------------------------

def export_markdown_summary(df: pd.DataFrame) -> str:
    """
    Generate a Markdown weekly summary report.
    """
    today = date.today().isoformat()
    total = len(df)
    open_df = df[df["status"].isin(["Open", "In Progress"])]
    mitigated = len(df[df["status"] == "Mitigated"])
    overdue_df = df[df["overdue"] == 1] if "overdue" in df.columns else pd.DataFrame()
    critical = len(df[df["severity"] == "Critical"])
    high = len(df[df["severity"] == "High"])

    sla_total = len(df[df["status"].isin(["Open", "In Progress", "Mitigated", "Accepted"])])
    if "overdue" in df.columns and sla_total:
        on_time = len(df[(df["overdue"] == 0) & (df["status"] != "")])
        sla_pct = round(on_time / sla_total * 100, 1)
    else:
        sla_pct = 100.0

    lines: list[str] = [
        "# Weekly Vulnerability Management Summary",
        f"**Report Date:** {today}  ",
        "**Prepared By:** Security Operations Team",
        "",
        "---",
        "",
        "## Executive Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Findings | {total} |",
        f"| Open / In Progress | {len(open_df)} |",
        f"| Critical | {critical} |",
        f"| High | {high} |",
        f"| Overdue | {len(overdue_df)} |",
        f"| Mitigated This Period | {mitigated} |",
        f"| SLA Compliance | {sla_pct}% |",
        "",
        "---",
        "",
        "## Top 5 Highest Risk Open Findings",
        "",
        "| # | Asset | CVE | Severity | Risk Score | Owner | Days Open |",
        "|---|-------|-----|----------|------------|-------|-----------|",
    ]

    top5 = open_df.nlargest(5, "risk_score") if "risk_score" in open_df.columns and not open_df.empty else open_df.head(5)
    for i, (_, row) in enumerate(top5.iterrows(), 1):
        try:
            days_open = (date.today() - date.fromisoformat(str(row.get("date_found", today)))).days
        except Exception:
            days_open = "N/A"
        lines.append(
            f"| {i} | {row.get('asset','')} | {row.get('cve','')} | "
            f"**{row.get('severity','')}** | {row.get('risk_score','')} | "
            f"{row.get('owner','')} | {days_open} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Overdue Findings by Owner",
        "",
    ]
    if overdue_df.empty:
        lines.append("✅ No overdue findings – SLA targets are being met.")
    else:
        for owner, grp in overdue_df.groupby("owner"):
            lines.append(f"### {owner} ({len(grp)} overdue)")
            lines.append("")
            lines.append("| Asset | CVE | Severity | Target Date |")
            lines.append("|-------|-----|----------|-------------|")
            for _, row in grp.iterrows():
                lines.append(
                    f"| {row.get('asset','')} | {row.get('cve','')} | "
                    f"{row.get('severity','')} | {row.get('target_date','')} |"
                )
            lines.append("")

    lines += [
        "---",
        "",
        "## Remediation Progress",
        "",
        "| Status | Count |",
        "|--------|-------|",
    ]
    for status, count in df["status"].value_counts().items():
        lines.append(f"| {status} | {count} |")

    lines += [
        "",
        "---",
        "",
        "## Recommended Actions",
        "",
    ]
    actions: list[str] = []
    if critical > 0:
        actions.append(
            f"1. **Immediate:** Patch or mitigate all **{critical} Critical** finding(s) within 7 days per policy."
        )
    if len(overdue_df) > 0:
        actions.append(
            f"2. **Escalate:** {len(overdue_df)} finding(s) are past SLA. "
            "Assign owners and set hard deadlines this week."
        )
    if sla_pct < 80:
        actions.append(
            f"3. **Process:** SLA compliance is at {sla_pct}% — consider additional remediation resources."
        )
    actions.append(
        "4. **Review:** Validate all 'Accepted' risks are formally approved by risk owner."
    )
    actions.append(
        "5. **Improve:** Schedule quarterly vulnerability scan to identify new exposures."
    )
    lines.extend(actions if actions else ["- No urgent actions required at this time."])

    lines += [
        "",
        "---",
        "",
        "*This report was auto-generated by VulnWatch.*",
    ]
    return "\n".join(lines)


def export_personal_findings_markdown(df: pd.DataFrame) -> str:
    """
    Generate a clean personal findings report in Markdown format.
    """
    today = date.today().isoformat()
    total = len(df)
    is_open = ~df["status"].str.lower().isin(["fixed", "mitigated", "ignored", "accepted"])
    open_df = df[is_open]
    critical = len(open_df[open_df["severity"] == "Critical"])
    high = len(open_df[open_df["severity"] == "High"])
    fixed = len(df[df["status"].str.lower().isin(["fixed", "mitigated"])])

    lines = [
        "# VulnWatch — Findings Summary",
        f"**Scan Report Date:** {today}  ",
        "**Scope:** Personal Devices & Home Lab",
        "",
        "---",
        "",
        "## Overview",
        "",
        f"- **Total Tracked Findings:** {total}",
        f"- **Open Findings:** {len(open_df)}",
        f"- **Critical Severity:** {critical}",
        f"- **High Severity:** {high}",
        f"- **Fixed / Mitigated:** {fixed}",
        f"- **Total Devices:** {df['asset'].nunique() if 'asset' in df.columns else 0}",
        "",
        "---",
        "",
        "## Active Findings",
        "",
        "| Device | Vulnerability | CVE | Severity | CVSS | Service/Port | Status |",
        "|--------|---------------|-----|----------|------|--------------|--------|",
    ]

    for _, r in open_df.sort_values("cvss", ascending=False).iterrows():
        port = f":{r['port']}" if pd.notna(r.get("port")) and r.get("port") else ""
        svc = f"{r.get('service','')}{port}".strip(":")
        lines.append(
            f"| {r.get('asset','')} | {r.get('vulnerability','')} | {r.get('cve','') or 'N/A'} | "
            f"**{r.get('severity','')}** | {r.get('cvss','')} | {svc} | {r.get('status','')} |"
        )

    lines += [
        "",
        "---",
        "",
        "*Generated by VulnWatch — Personal Vulnerability Scanner.*",
    ]
    return "\n".join(lines)
