"""
tests/test_scoring.py
=====================
Unit tests for the risk scoring engine and SLA logic.
"""

from datetime import date, timedelta

import pytest

from core.scoring import (
    compute_risk_score,
    cvss_to_severity,
    is_overdue,
    sla_target_date,
    SLA_DAYS,
)


# ---------------------------------------------------------------------------
# cvss_to_severity
# ---------------------------------------------------------------------------

class TestCvssToSeverity:
    def test_critical_exact(self):
        assert cvss_to_severity(9.0) == "Critical"

    def test_critical_max(self):
        assert cvss_to_severity(10.0) == "Critical"

    def test_high_lower(self):
        assert cvss_to_severity(7.0) == "High"

    def test_high_upper(self):
        assert cvss_to_severity(8.9) == "High"

    def test_medium_lower(self):
        assert cvss_to_severity(4.0) == "Medium"

    def test_medium_upper(self):
        assert cvss_to_severity(6.9) == "Medium"

    def test_low(self):
        assert cvss_to_severity(2.5) == "Low"

    def test_informational(self):
        assert cvss_to_severity(0.0) == "Informational"

    def test_boundary_9(self):
        assert cvss_to_severity(8.99) == "High"


# ---------------------------------------------------------------------------
# compute_risk_score
# ---------------------------------------------------------------------------

class TestComputeRiskScore:
    def test_critical_high_asset(self):
        # 10.0 * 1.0 (Critical) * 1.0 (High) * 10 = 100.0
        assert compute_risk_score(10.0, "High") == 100.0

    def test_critical_medium_asset(self):
        # 10.0 * 1.0 * 0.75 * 10 = 75.0
        assert compute_risk_score(10.0, "Medium") == 75.0

    def test_critical_low_asset(self):
        # 10.0 * 1.0 * 0.50 * 10 = 50.0
        assert compute_risk_score(10.0, "Low") == 50.0

    def test_high_medium_asset(self):
        # 7.5 * 0.75 * 0.75 * 10 = 42.2
        assert compute_risk_score(7.5, "Medium") == pytest.approx(42.2, abs=0.2)

    def test_low_cvss_clamped_to_zero(self):
        assert compute_risk_score(0.0, "High") == 0.0

    def test_score_never_exceeds_100(self):
        assert compute_risk_score(10.0, "High") <= 100.0

    def test_score_never_below_zero(self):
        assert compute_risk_score(-1.0, "High") >= 0.0

    def test_unknown_criticality_defaults_medium(self):
        # Should not raise; unknown criticality defaults to 0.75
        score = compute_risk_score(7.5, "Unknown")  # type: ignore
        assert score >= 0.0


# ---------------------------------------------------------------------------
# sla_target_date
# ---------------------------------------------------------------------------

class TestSlaTargetDate:
    def test_critical_7_days(self):
        found = date(2024, 1, 1)
        expected = date(2024, 1, 8)
        assert sla_target_date("Critical", found) == expected

    def test_high_30_days(self):
        found = date(2024, 1, 1)
        expected = date(2024, 1, 31)
        assert sla_target_date("High", found) == expected

    def test_medium_90_days(self):
        found = date(2024, 1, 1)
        expected = date(2024, 3, 31)  # 90 days (2024 is leap year)
        assert sla_target_date("Medium", found) == expected

    def test_low_180_days(self):
        found = date(2024, 1, 1)
        expected = date(2024, 6, 29)  # 180 days (2024 is leap year)
        assert sla_target_date("Low", found) == expected

    def test_all_severities_have_sla(self):
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            result = sla_target_date(sev, date.today())  # type: ignore
            assert result > date.today()


# ---------------------------------------------------------------------------
# is_overdue
# ---------------------------------------------------------------------------

class TestIsOverdue:
    def _past_date(self, days: int) -> date:
        return date.today() - timedelta(days=days)

    def test_critical_overdue_after_8_days(self):
        found = self._past_date(8)  # 8 days ago, SLA is 7
        assert is_overdue("Critical", found, "Open") is True

    def test_critical_not_overdue_at_6_days(self):
        found = self._past_date(6)  # 6 days ago, SLA is 7
        assert is_overdue("Critical", found, "Open") is False

    def test_mitigated_never_overdue(self):
        found = self._past_date(365)  # Very old
        assert is_overdue("Critical", found, "Mitigated") is False

    def test_accepted_never_overdue(self):
        found = self._past_date(365)
        assert is_overdue("High", found, "Accepted") is False

    def test_in_progress_can_be_overdue(self):
        found = self._past_date(35)  # Past High SLA of 30 days
        assert is_overdue("High", found, "In Progress") is True

    def test_custom_reference_date(self):
        found = date(2024, 1, 1)
        ref = date(2024, 1, 9)  # 8 days later, Critical SLA=7
        assert is_overdue("Critical", found, "Open", reference_date=ref) is True

    def test_custom_reference_date_before_sla(self):
        found = date(2024, 1, 1)
        ref = date(2024, 1, 5)  # 4 days later, Critical SLA=7
        assert is_overdue("Critical", found, "Open", reference_date=ref) is False
