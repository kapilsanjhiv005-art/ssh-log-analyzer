"""Tests for the dashboard's shared analysis helper."""

from datetime import date, datetime, timedelta

from analyzer import render_csv
from dashboard import (
    analyze_for_dashboard,
    filter_dashboard_data,
    risk_band_badge,
    summarize_dashboard_metrics,
)
from detections import analyze_events
from html_report import render_html_report


def test_dashboard_risk_badge_uses_critical_color_and_escapes_label():
    badge = risk_band_badge("Critical")
    assert "#ffebee" in badge
    assert ">Critical</span>" in badge
    assert "&lt;script&gt;" in risk_band_badge("<script>")


def test_dashboard_analysis_uses_shared_web_pipeline_and_allowlist(tmp_path):
    log = tmp_path / "access.log"
    row = '192.0.2.7 - - [19/Oct/2026:08:00:00 +0000] "POST /login HTTP/1.1" 401 12 "-" "Browser"'
    log.write_text("\n".join([row] * 5) + "\n", encoding="utf-8")

    events, stats, result = analyze_for_dashboard(
        log,
        log_type="web",
        year=2026,
        allowlist_text="# trusted test source\n192.0.2.0/24\n",
    )

    assert len(events) == 5
    assert events[0]["timestamp"] == datetime(2026, 10, 19, 8)
    assert stats["events_parsed"] == 5
    assert result["alerts"] == []
    assert result["alerts_suppressed"] == 1


def test_dashboard_analysis_respects_threshold_and_reports_shared_alert(tmp_path):
    log = tmp_path / "access.log"
    row = '192.0.2.7 - - [19/Oct/2026:08:00:00 +0000] "POST /login HTTP/1.1" 401 12 "-" "Browser"'
    log.write_text("\n".join([row] * 5) + "\n", encoding="utf-8")

    _, _, result = analyze_for_dashboard(log, log_type="web", year=2026, threshold=5)

    assert result["alerts"][0]["rule"] == "web_login_bruteforce"
    assert result["alerts"][0]["mitre_attack_id"] == "T1110"


def test_dashboard_metrics_separate_rule_severity_from_unique_source_risk():
    alerts = [
        {"severity": "Critical", "base_severity": "Low", "source_ip": "192.0.2.10"},
        {"severity": "Medium", "base_severity": "Medium", "source_ip": "192.0.2.10"},
    ]
    metrics = summarize_dashboard_metrics(
        alerts, {"192.0.2.10": {"score": 86, "band": "Critical"}}, []
    )

    assert metrics["critical_alerts"] == 0
    assert metrics["low_alerts"] == 1
    assert metrics["medium_alerts"] == 1
    assert metrics["critical_risk_sources"] == 1


def test_dashboard_metrics_are_zero_for_empty_analysis():
    metrics = summarize_dashboard_metrics([], {}, [])
    assert all(value == 0 for value in metrics.values())


def test_dashboard_filter_uses_source_and_inclusive_date_without_mutation():
    start = datetime(2026, 10, 19, 8)
    events = [
        {"timestamp": start, "source_ip": "192.0.2.10", "event_type": "authentication_failure"},
        {
            "timestamp": start + timedelta(days=1),
            "source_ip": "192.0.2.11",
            "event_type": "authentication_failure",
        },
    ]
    result = analyze_events(events)

    filtered_events, filtered_result = filter_dashboard_data(
        events,
        result,
        source_ip="192.0.2.10",
        start_date=date(2026, 10, 19),
        end_date=date(2026, 10, 19),
    )

    assert len(filtered_events) == 1
    assert set(filtered_result["risk_scores"]) == {"192.0.2.10"}
    assert len(events) == 2


def test_dashboard_filter_handles_empty_range():
    filtered_events, filtered_result = filter_dashboard_data(
        [],
        {"alerts": [], "risk_scores": {}, "incidents": []},
        start_date=date(2026, 10, 19),
        end_date=date(2026, 10, 19),
    )
    assert filtered_events == []
    assert filtered_result["risk_scores"] == {}
    assert filtered_result["incidents"] == []


def test_incident_selection_id_is_stable_under_source_filter():
    start = datetime(2026, 10, 19, 8)
    events = [
        {
            "timestamp": start + timedelta(seconds=offset),
            "source_ip": "192.0.2.10",
            "event_type": "authentication_failure",
            "username": username,
        }
        for offset, username in enumerate(("a", "b", "c", "d", "e"))
    ]
    result = analyze_events(events)
    all_incident = result["incidents"][0]
    _, source_view = filter_dashboard_data(events, result, source_ip="192.0.2.10")

    assert source_view["incidents"][0]["incident_id"] == all_incident["incident_id"]


def test_dashboard_filters_drop_missing_timestamp_rows_safely():
    events = [
        {"source_ip": "192.0.2.10", "event_type": "authentication_failure"},
        {
            "timestamp": datetime(2026, 10, 19),
            "source_ip": "192.0.2.10",
            "event_type": "authentication_failure",
        },
    ]
    visible, _ = filter_dashboard_data(events, {"alerts": [], "risk_scores": {}, "incidents": []})
    assert len(visible) == 1


def test_filtered_download_sources_match_dashboard_scope():
    first = datetime(2026, 10, 19, 8)
    events = [
        {
            "timestamp": first + timedelta(seconds=offset),
            "source_ip": source_ip,
            "event_type": "authentication_failure",
            "username": "analyst",
        }
        for source_ip, base in (("192.0.2.10", first), ("192.0.2.11", first + timedelta(days=1)))
        for offset in range(5)
    ]
    result = analyze_events(events)
    filtered_events, filtered_result = filter_dashboard_data(
        events,
        result,
        source_ip="192.0.2.10",
        start_date=date(2026, 10, 19),
        end_date=date(2026, 10, 19),
    )

    csv_text = render_csv(filtered_result["alerts"])
    html_text = render_html_report(filtered_events, filtered_result)

    assert len(filtered_result["alerts"]) == 1
    assert set(filtered_result["risk_scores"]) == {"192.0.2.10"}
    assert "192.0.2.11" not in csv_text
    assert "192.0.2.11" not in html_text
