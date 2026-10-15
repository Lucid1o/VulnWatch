"""
core/scoring.py
===============
Risk Scoring Engine
-------------------
Formula (documented):

  CVSS Base Score  → Severity bucket
    9.0 – 10.0     → Critical  (weight 1.0)
    7.0 –  8.9     → High      (weight 0.75)
    4.0 –  6.9     → Medium    (weight 0.40)
    0.1 –  3.9     → Low       (weight 0.15)
    0.0            → Informational (weight 0.05)

  Asset Criticality Multiplier
    High   → 1.0
    Medium → 0.75
    Low    → 0.50

  Final Risk Score (0-100)
    risk_score = round(cvss_score * severity_weight * criticality_multiplier * 10, 1)
    clamped to [0, 100]

SLA Targets (days from date_found)
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
# Severity
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

# SLA in calendar days
SLA_DAYS: dict[SeverityLabel, int] = {
    "Critical": 7,
    "High": 30,
    "Medium": 90,
    "Low": 180,
    "Informational": 365,
}


def cvss_to_severity(cvss: float) -> SeverityLabel:
    """Map a CVSS base score (0-10) to a severity label."""
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
) -> float:
    """
    Compute a final risk score in [0, 100].

    Parameters
    ----------
    cvss:
        CVSS base score, 0.0-10.0.
    asset_criticality:
        Business criticality of the affected asset.

    Returns
    -------
    float
        Rounded risk score clamped to [0, 100].
    """
    severity = cvss_to_severity(cvss)
    weight = _SEVERITY_WEIGHTS[severity]
    multiplier = _CRITICALITY_MULTIPLIERS.get(asset_criticality, 0.75)
    score = cvss * weight * multiplier * 10.0
    return round(min(max(score, 0.0), 100.0), 1)


def sla_target_date(severity: SeverityLabel, date_found: date) -> date:
    """Return the SLA target remediation date."""
    days = SLA_DAYS.get(severity, 90)
    return date_found + timedelta(days=days)


def is_overdue(severity: SeverityLabel, date_found: date, status: str, reference_date: date | None = None) -> bool:
    """
    Return True if the finding is past its SLA target and not yet remediated.

    Mitigated / Accepted findings are NOT considered overdue.
    """
    if status in ("Mitigated", "Accepted"):
        return False
    ref = reference_date or date.today()
    return ref > sla_target_date(severity, date_found)
