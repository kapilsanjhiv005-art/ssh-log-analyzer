"""HTML report escaping, embedding, and empty-state tests."""

from datetime import datetime

from html_report import render_html_report


def test_report_escapes_log_derived_username_and_user_agent():
    payload = "<script>alert(1)</script>"
    events = [
        {
            "timestamp": datetime(2026, 10, 19, 2),
            "source_ip": "198.51.100.10",
            "username": payload,
            "event_type": "authentication_failure",
            "user_agent": payload,
            "status": 401,
        }
    ]
    alert = {
        "rule": "web_suspicious_user_agent",
        "severity": "Low",
        "source_ip": "198.51.100.10",
        "first_seen": datetime(2026, 10, 19, 2),
        "last_seen": datetime(2026, 10, 19, 2),
        "attempt_count": 1,
        "usernames_targeted": [payload],
        "description": "Suspicious web user agent observed.",
        "recommended_action": "Review the source.",
        "user_agent": payload,
    }
    document = render_html_report(
        events,
        {
            "alerts": [alert],
            "incidents": [],
            "risk_scores": {"198.51.100.10": {"score": 10, "band": "Low"}},
            "alerts_suppressed": 0,
            "parse_stats": {"events_parsed": 1, "lines_ignored": 0, "lines_malformed": 0},
            "version": "test",
            "generated_at": "2026-10-19T00:00:00+00:00",
            "config_used": {},
        },
    )

    assert payload not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    assert "data:image/png;base64," in document
    assert "https://" not in document
    assert "No correlated incidents." in render_html_report(
        [],
        {
            "alerts": [],
            "incidents": [],
            "risk_scores": {},
            "alerts_suppressed": 0,
            "parse_stats": {},
            "config_used": {},
        },
    )
