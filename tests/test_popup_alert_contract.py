#!/usr/bin/env python3
"""Regression tests for security incident popup notifications."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.app.api.v1.endpoints.network_defense import (  # noqa: E402
    _build_event_anomaly_context,
    ThreatSeverity,
)


def test_dashboard_popup_contract_covers_sql_and_xss_variants():
    html = (ROOT / "server/app/static/index.html").read_text(encoding="utf-8")
    lower = html.lower()

    assert "handlerealtimelogevent" in lower
    assert "buildsecuritypromptpayloadfromthreat" in lower
    assert "buildsecuritypromptpayloadfromlog" in lower
    assert "showtoast" in lower
    assert "stored xss" in lower
    assert "reflected xss" in lower
    assert "dom xss" in lower
    assert "sql injection" in lower
    assert "sqli" in lower


def test_backend_anomaly_context_scores_sql_and_xss_incidents():
    xss_context = _build_event_anomaly_context(
        event_name="stored xss payload",
        severity=ThreatSeverity.HIGH,
        recent_count=3,
        description="Reflected XSS attempt with <script>alert(1)</script>",
        payload={"indicator": "javascript:", "details": "dom xss"},
    )

    sql_context = _build_event_anomaly_context(
        event_name="sql injection",
        severity=ThreatSeverity.HIGH,
        recent_count=6,
        description="union select drop table attempt",
        payload={"indicator": "union select", "details": "sqli"},
    )

    assert xss_context["anomaly_score"] > 0.20
    assert sql_context["anomaly_score"] > xss_context["anomaly_score"]
    assert xss_context["risk_level"] == "low"
    assert sql_context["risk_level"] == "low"
    assert any(signal.startswith("markers:") for signal in xss_context["signals"])
    assert any(signal.startswith("markers:") for signal in sql_context["signals"])
    assert any("burst:" in signal for signal in sql_context["signals"])