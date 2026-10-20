"""Tests for the dashboard's safe, deterministic Markdown export."""

from markdown_report import render_markdown_report


def test_markdown_report_separates_severity_and_risk_and_escapes_log_text():
    report = render_markdown_report(
        {
            "alerts": [
                {
                    "rule": "ssh_brute_force",
                    "severity": "Low",
                    "base_severity": "Low",
                    "source_ip": "192.0.2.10",
                    "first_seen": "2026-10-19T09:00:00",
                    "attempt_count": 5,
                    "description": "<script>alert(1)</script> | [click](https://example.invalid)",
                }
            ],
            "incidents": [],
            "risk_scores": {"192.0.2.10": {"score": 86, "band": "Critical"}},
            "parse_stats": {"lines_read": 5, "events_parsed": 5},
        }
    )

    assert "Low 1" in report
    assert "86 / Critical" in report
    assert (
        r"&lt;script&gt;alert\(1\)&lt;/script&gt; &#124; \[click\]"
        r"\(https://example\.invalid\)"
    ) in report
    assert "<script>" not in report


def test_empty_markdown_report_has_explicit_empty_states():
    report = render_markdown_report({})
    assert "No correlated incidents" in report
    assert "No alerts were generated" in report


def test_markdown_report_includes_timestamp_interpretation():
    report = render_markdown_report(
        {
            "timestamp_interpretation": {
                "year_for_yearless_timestamps": 2016,
                "timezone_assumption": "timezone-unspecified SSH syslog timestamps",
                "offset_timestamp_policy": "timestamps with explicit offsets are normalized to UTC",
            }
        }
    )

    assert "Timestamp interpretation" in report
    assert r"timezone\-unspecified SSH syslog timestamps" in report
    assert "normalized to UTC" in report


def test_markdown_report_includes_successful_login_evidence():
    report = render_markdown_report(
        {
            "risk_explanations": {
                "192.0.2.70": {
                    "score": 40,
                    "band": "Medium",
                    "factors": {
                        "root_targeting": {
                            "evidence": 1,
                            "contribution": 15,
                            "policy": "Add 15 points when root failure is observed.",
                        }
                    },
                    "confidence": {"rationale": "not calibrated"},
                    "uncertainty": "shared NAT caveat",
                }
            },
            "successful_logins": [
                {
                    "timestamp": "2016-12-10T09:32:20",
                    "source_ip": "192.0.2.70",
                    "username": "analyst",
                    "duration_seconds": 766,
                    "related_failures": 0,
                    "correlation_status": "unique lifecycle",
                }
            ],
        }
    )

    assert "## Successful logins" in report
    assert r"192\.0\.2\.70" in report
    assert "766" in report
    assert "## Source-risk explanations" in report
    assert "shared NAT caveat" in report


def test_markdown_summary_distinguishes_password_failures_and_none_probes():
    from markdown_report import render_markdown_report

    report = render_markdown_report(
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
                "root_authentication_failures": 0,
                "root_authentication_successes": 0,
                "root_password_authentication_failures": 0,
                "effective_authentication_attempts": 2,
            },
        }
    )

    assert "Password failures: 1" in report
    assert "Failed none probes: 1" in report
