"""
tests/test_app_pages.py
=======================
Automated render testing for all VulnWatch pages across Personal Mode and Team Mode
using Streamlit's native AppTest framework.
"""

from __future__ import annotations

import pytest
from streamlit.testing.v1 import AppTest
from core.database import init_db, get_connection, insert_findings, clear_db
from core.demo_data import generate_demo_findings


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    conn = get_connection()
    init_db(conn)
    clear_db(conn)
    findings = generate_demo_findings(20, seed=42, team_mode=False)
    insert_findings(conn, findings)
    yield
    clear_db(conn)


def test_personal_mode_renders_all_pages():
    """Test Personal Mode: Overview, Devices, Findings, Run Scan, History."""
    at = AppTest.from_file("../app.py", default_timeout=30)
    at.session_state["team_mode"] = False
    at.run()
    assert not at.exception, f"Overview page raised exception: {at.exception}"

    # Verify radio exists and contains personal mode pages
    assert len(at.radio) > 0
    radio = at.radio[0]
    expected_pages = [
        "🏠 Overview",
        "💻 Devices",
        "🔍 Findings",
        "🎯 Run Scan",
        "📜 History",
    ]
    assert radio.options == expected_pages

    # Cycle through each page and confirm it executes cleanly
    for page_name in expected_pages:
        radio.set_value(page_name)
        at.run()
        assert not at.exception, f"Page {page_name} raised exception: {at.exception}"


def test_team_mode_renders_all_pages(monkeypatch):
    """Test Team Mode: Executive Summary, Risk Register, Remediation, Compliance, etc."""
    # Mock config to enable team_mode
    import core.config
    monkeypatch.setattr(core.config, "load_config", lambda *args, **kwargs: {"team_mode": True, "app_name": "VulnWatch"})

    at = AppTest.from_file("../app.py", default_timeout=30)
    at.session_state["team_mode"] = True
    at.run()
    assert not at.exception, f"Team Mode initial page raised exception: {at.exception}"

    radio = at.radio[0]
    expected_team_pages = [
        "📊 Executive Summary",
        "📋 Risk Register",
        "🔧 Remediation Tracker",
        "📐 Compliance View",
        "🎯 Live Network Scan",
        "📥 Data Ingestion",
        "📤 Export Reports",
    ]
    assert radio.options == expected_team_pages

    # Cycle through each team mode page and confirm it executes cleanly
    for page_name in expected_team_pages:
        radio.set_value(page_name)
        at.run()
        assert not at.exception, f"Team page {page_name} raised exception: {at.exception}"
