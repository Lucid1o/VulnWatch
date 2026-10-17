"""
core/scoring.py
===============
VulnWatch Scoring Engine
------------------------
Personal Mode (Default):
  - Severity is mapped directly from CVSS 3.x bands:
      9.0 – 10.0     → Critical
      7.0 –  8.9     → High
      4.0 –  6.9     → Medium
      0.1 –  3.9     → Low
      0.0            → Informational
    or determined by risky-service rules.
  - No asset criticality weighting is applied in personal mode.

Team Mode (Optional, behind config flag):
  - Asset Criticality Multipliers:
      High   → 1.0
      Medium → 0.75
      Low    → 0.50
  - Risk Score formula clamped to [0, 100]:
      risk_score = round(cvss_score * severity_weight * criticality_multiplier * 10, 1)
  - SLA Remediation Targets:
      Critical → 7 days
      High     → 30 days
      Medium   → 90 days
      Low      → 180 days
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Literal

SeverityLabel = Literal["Critical", "High", "Medium", "Low", "Informational"]
CriticalityLabel = Literal["High", "Medium", "Low"]

# ---------------------------------------------------------------------------
# Severity Weights and Criticality Multipliers
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[SeverityLabel, float] = {
    "Critical": 1.00,
    "High": 0.75,
    "Medium": 0.40,
    "Low": 0.15,
    "Informational": 0.05,
}

_CRITICALITY_MULTIPLIERS: dict[CriticalityLabel, float] = {
    "High": 1.00,
    "Medium": 0.75,
    "Low": 0.50,
}

# SLA in calendar days (used in Team Mode)
SLA_DAYS: dict[SeverityLabel, int] = {
    "Critical": 7,
    "High": 30,
    "Medium": 90,
    "Low": 180,
    "Informational": 365,
}


def cvss_to_severity(cvss: float) -> SeverityLabel:
    """
    Map a CVSS base score (0.0-10.0) directly to a standard severity band.

    Bands
    -----
    9.0 - 10.0 : Critical
    7.0 -  8.9 : High
    4.0 -  6.9 : Medium
    0.1 -  3.9 : Low
    0.0        : Informational
    """
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0.0:
        return "Low"
    return "Informational"


def compute_risk_score(
    cvss: float,
    asset_criticality: CriticalityLabel = "Medium",
    team_mode: bool = True,
) -> float:
    """
    Compute risk score in [0, 100].

    Parameters
    ----------
    cvss:
        CVSS base score (0.0 - 10.0).
    asset_criticality:
        Asset criticality level ('High', 'Medium', 'Low').
        Ignored when team_mode is False.
    team_mode:
        If True, applies asset criticality weighting.
        If False (personal mode), applies no asset weighting.

    Returns
    -------
    float
        Rounded risk score clamped to [0, 100].
    """
    severity = cvss_to_severity(cvss)
    weight = _SEVERITY_WEIGHTS[severity]

    if not team_mode:
        # In personal mode: severity directly from CVSS bands, no asset weighting
        score = cvss * weight * 10.0
    else:
        multiplier = _CRITICALITY_MULTIPLIERS.get(asset_criticality, 0.75)
        score = cvss * weight * multiplier * 10.0

    return round(min(max(score, 0.0), 100.0), 1)


def sla_target_date(severity: SeverityLabel, date_found: date) -> date:
    """Return the SLA target remediation date (team mode)."""
    days = SLA_DAYS.get(severity, 90)
    return date_found + timedelta(days=days)


def is_overdue(
    severity: SeverityLabel,
    date_found: date,
    status: str,
    reference_date: date | None = None,
) -> bool:
    """
    Return True if the finding is past its SLA target and not yet remediated.

    Mitigated / Accepted / Fixed / Ignored findings are NOT considered overdue.
    """
    normalized_status = str(status).strip().lower()
    if normalized_status in ("mitigated", "accepted", "fixed", "ignored"):
        return False
    ref = reference_date or date.today()
    return ref > sla_target_date(severity, date_found)
