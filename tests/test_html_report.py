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


def test_incident_evidence_fields_are_rendered_and_escaped():
    incident = {
        "incident_id": "INC-001",
        "combined_severity": "High",
        "risk_score": 60,
        "risk_band": "High",
        "source_ip": "192.0.2.10",
        "first_seen": "2026-10-19T08:00:00",
        "last_seen": "2026-10-19T08:00:05",
        "attempt_count": 5,
        "usernames_targeted": ["<script>alert(1)</script>"],
        "authentication_methods": ["password"],
        "contributing_rules": ["ssh_brute_force", "ssh_password_spraying"],
        "summary": "two related rules",
    }
    document = render_html_report([], {"alerts": [], "incidents": [incident], "risk_scores": {}})

    assert "5</td>" in document
    assert "password" in document
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document


def test_html_report_includes_timestamp_interpretation():
    report = render_html_report(
        [],
        {
            "alerts": [],
            "incidents": [],
            "timestamp_interpretation": {
                "year_for_yearless_timestamps": 2016,
                "timezone_assumption": "timezone-unspecified SSH syslog timestamps",
                "offset_timestamp_policy": "timestamps with explicit offsets are normalized to UTC",
            },
        },
    )

    assert "Timestamp interpretation" in report
    assert "timezone-unspecified SSH syslog timestamps" in report
    assert "normalized to UTC" in report


def test_html_report_includes_escaped_successful_login_evidence():
    username = "<script>login()</script>"
    report = render_html_report(
        [],
        {
            "alerts": [],
            "incidents": [],
            "risk_explanations": {
                "192.0.2.70": {
                    "score": 40,
                    "band": "Medium",
                    "factors": {
                        "root_targeting": {
                            "evidence": 1,
                            "contribution": 15,
                            "policy": "Add points when root failure is observed.",
                        }
                    },
                    "confidence": {"rationale": "not a calibrated probability"},
                    "uncertainty": "shared NAT may group unrelated users",
                }
            },
            "successful_logins": [
                {
                    "timestamp": "2016-12-10T09:32:20",
                    "source_ip": "192.0.2.70",
                    "username": username,
                    "duration_seconds": 766,
                    "session_identifier": None,
                    "data_quality_limitations": ["unknown session ID"],
                }
            ],
        },
    )

    assert username not in report
    assert "&lt;script&gt;login()&lt;/script&gt;" in report
    assert "Successful logins" in report
    assert "766" in report
    assert "Source-risk explanations" in report
    assert "shared NAT may group unrelated users" in report


def test_html_summary_distinguishes_password_failures_and_none_probes():
    html = render_html_report(
        [],
        {
            "alerts": [],
            "incidents": [],
            "risk_scores": {},
            "parse_stats": {
                "lines_read": 2,
                "events_parsed": 2,
                "authentication_failures": 2,
                "password_authentication_failures": 1,
                "authentication_method_probes": 1,
                "authentication_successes": 0,
                "root_authentication_failures": 1,
                "root_password_authentication_failures": 0,
                "root_authentication_successes": 0,
            },
        },
    )

    assert "1 password failures" in html
    assert "1 Failed none probes" in html
