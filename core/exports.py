"""
core/exports.py
===============
Reporting: Excel workbook and Markdown management summary.
"""

from __future__ import annotations

import io
from datetime import date, datetime
from typing import Any

import pandas as pd


# ---------------------------------------------------------------------------
# Excel Export
# ---------------------------------------------------------------------------

# Severity colour fill (ARGB)
_SEV_FILLS = {
    "Critical": "FFDC2626",
    "High":     "FFEA580C",
    "Medium":   "FFEAB308",
    "Low":      "FF22C55E",
}


def export_excel(df: pd.DataFrame) -> bytes:
    """
    Build a multi-sheet Excel workbook and return raw bytes.

    Sheets
    ------
    Summary   – KPI table
    Register  – Full risk register with colour coding
    Overdue   – Filtered overdue findings
    Charts    – Severity distribution (data table for charting)
    """
    buf = io.BytesIO()
    today = date.today().isoformat()

    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        wb = writer.book

        # ---- helpers -------------------------------------------------------
        from openpyxl.styles import (
            PatternFill, Font, Alignment, Border, Side, numbers
        )
        from openpyxl.utils import get_column_letter
        from openpyxl.chart import BarChart, Reference

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
        ws_sum["A1"] = "Vulnerability & Risk Management – Executive Summary"
        ws_sum["A1"].font = title_font
        ws_sum["A2"] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        ws_sum["A2"].font = Font(italic=True, color="FF666666")
        ws_sum.merge_cells("A1:D1")

        kpis = [
            ("Total Findings",          len(df)),
            ("Open",                    len(df[df["status"].isin(["Open", "In Progress"])])),
            ("Critical",                len(df[df["severity"] == "Critical"])),
            ("High",                    len(df[df["severity"] == "High"])),
            ("Overdue",                 int(df["overdue"].sum())),
            ("Mitigated",               len(df[df["status"] == "Mitigated"])),
            ("Avg Risk Score",          round(df["risk_score"].mean(), 1) if len(df) else 0),
            ("Report Date",             today),
        ]
        ws_sum.append([])
        ws_sum.append(["Metric", "Value"])
        style_header(ws_sum, ws_sum.max_row, 2)
        for label, val in kpis:
            ws_sum.append([label, val])
        auto_width(ws_sum)

        # ---- Register Sheet ------------------------------------------------
        register_cols = [
            "id", "asset", "asset_type", "asset_criticality", "cve", "cvss",
            "severity", "risk_score", "vulnerability", "service", "owner",
            "status", "date_found", "target_date", "overdue", "notes",
            "nist_csf", "iso_control",
        ]
        export_df = df[[c for c in register_cols if c in df.columns]].copy()
        export_df.to_excel(writer, sheet_name="Register", index=False, startrow=1)
        ws_reg = writer.sheets["Register"]
        ws_reg.sheet_view.showGridLines = False
        style_header(ws_reg, 2, len(export_df.columns))

        # Colour severity column
        sev_col_idx = list(export_df.columns).index("severity") + 1 if "severity" in export_df.columns else None
        if sev_col_idx:
            for row_idx in range(3, ws_reg.max_row + 1):
                cell = ws_reg.cell(row=row_idx, column=sev_col_idx)
                fill_color = _SEV_FILLS.get(str(cell.value), "FFFFFFFF")
                cell.fill = PatternFill("solid", fgColor=fill_color)
                cell.font = Font(color="FFFFFFFF", bold=True)
        auto_width(ws_reg)

        # ---- Overdue Sheet -------------------------------------------------
        overdue_df = df[df["overdue"] == 1][
            [c for c in ["id", "asset", "cve", "severity", "risk_score", "owner", "date_found", "target_date", "status"] if c in df.columns]
        ]
        overdue_df.to_excel(writer, sheet_name="Overdue", index=False, startrow=1)
        ws_ov = writer.sheets["Overdue"]
        ws_ov.sheet_view.showGridLines = False
        style_header(ws_ov, 2, len(overdue_df.columns))
        auto_width(ws_ov)

        # ---- Charts Data Sheet ---------------------------------------------
        sev_counts = df["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        sev_counts.to_excel(writer, sheet_name="Charts", index=False)

        # Severity bar chart
        ws_ch = writer.sheets["Charts"]
        chart = BarChart()
        chart.type = "col"
        chart.title = "Findings by Severity"
        chart.y_axis.title = "Count"
        chart.x_axis.title = "Severity"
        data_ref = Reference(ws_ch, min_col=2, min_row=1, max_row=len(sev_counts) + 1)
        cats_ref = Reference(ws_ch, min_col=1, min_row=2, max_row=len(sev_counts) + 1)
        chart.add_data(data_ref, titles_from_data=True)
        chart.set_categories(cats_ref)
        chart.shape = 4
        ws_ch.add_chart(chart, "D2")

        # Remove the default first sheet if empty
        if "Sheet" in wb.sheetnames:
            del wb["Sheet"]

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Markdown / Management Summary Export
# ---------------------------------------------------------------------------

def export_markdown_summary(df: pd.DataFrame) -> str:
    """
    Generate a Markdown weekly management summary.

    Sections
    --------
    - Overview KPIs
    - Top 5 Risks (highest risk_score, open)
    - Overdue Findings by Owner
    - Progress (status distribution)
    - Recommended Actions
    """
    today = date.today().isoformat()
    total = len(df)
    open_df = df[df["status"].isin(["Open", "In Progress"])]
    mitigated = len(df[df["status"] == "Mitigated"])
    overdue_df = df[df["overdue"] == 1]
    critical = len(df[df["severity"] == "Critical"])
    high = len(df[df["severity"] == "High"])

    sla_total = len(df[df["status"].isin(["Open", "In Progress", "Mitigated", "Accepted"])])
    on_time = len(df[(df["overdue"] == 0) & (df["status"] != "")]) 
    sla_pct = round(on_time / sla_total * 100, 1) if sla_total else 100.0

    lines: list[str] = [
        f"# Weekly Vulnerability Management Summary",
        f"**Report Date:** {today}  ",
        f"**Prepared By:** Security Operations Team",
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

    top5 = open_df.nlargest(5, "risk_score")
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
        "*This report was auto-generated by the Vulnerability & Risk Management Dashboard.*",
    ]
    return "\n".join(lines)
