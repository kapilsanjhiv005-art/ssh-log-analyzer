"""End-to-end checks for weighted OpenSSH syslog repeated-message records."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from analyzer import export_json, print_summary, render_csv
from dashboard import _attempts_by_hour, analyze_for_dashboard, summarize_dashboard_metrics
from detections import analyze_events
from html_report import render_html_report
from markdown_report import render_markdown_report
from ssh_parser import parse_log_file

FIXTURE = Path(__file__).parents[1] / "sample_logs" / "repeated_syslog_semantics.log"


def test_repeated_syslog_weight_is_consistent_across_analysis_and_reports(tmp_path, capsys):
    """A standalone original plus N suppressed copies represents N+1 events."""
    events, parse_stats = parse_log_file(FIXTURE, year=2026)
    effective_events = sum(event["occurrence_count"] for event in events)

    assert parse_stats["lines_read"] == 2
    assert parse_stats["events_parsed"] == 2
    assert effective_events == 5
    assert sum(event["event_type"] == "authentication_failure" for event in events) == 2
    assert (
        sum(
            event["occurrence_count"]
            for event in events
            if event["event_type"] == "authentication_failure"
        )
        == 5
    )
    assert sum(event["occurrence_count"] for event in events if event.get("is_root")) == 5

    result = analyze_events(events)
    report_result = {**result, "parse_stats": parse_stats}
    brute_force = next(alert for alert in result["alerts"] if alert["rule"] == "ssh_brute_force")
    root_attempts = next(
        alert for alert in result["alerts"] if alert["rule"] == "ssh_root_login_attempt"
    )
    assert brute_force["attempt_count"] == root_attempts["attempt_count"] == 5
    assert len(result["incidents"]) == 1
    assert result["incidents"][0]["attempt_count"] == 5

    # Every export carries the same alert and incident attempt totals.
    json_path = export_json(report_result, tmp_path / "result.json")
    json_result = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_result["parse_stats"]["effective_event_occurrences"] == 5
    assert json_result["parse_stats"]["authentication_failures"] == 5
    assert json_result["parse_stats"]["root_authentication_failures"] == 5
    assert {alert["attempt_count"] for alert in json_result["alerts"]} == {5}
    assert json_result["incidents"][0]["attempt_count"] == 5
    csv_rows = list(csv.DictReader(render_csv(result["alerts"]).splitlines()))
    assert {int(row["attempt_count"]) for row in csv_rows} == {5}
    html_report = render_html_report(events, report_result)
    markdown_report = render_markdown_report(report_result)
    assert html_report.count("<td>5</td>") >= 3
    assert "5 failures" in html_report
    assert "5 terminal authentication attempts" in html_report
    assert markdown_report.count("| 5 |") >= 3
    assert "- Terminal authentication attempts: 5" in markdown_report
    assert "- Failed authentication attempts: 5" in markdown_report
    assert "- Root authentication failures: 5" in markdown_report
    incident_section = markdown_report.split("## Incidents", 1)[1].split("## Alerts", 1)[0]
    assert "| 5 |" in incident_section
    assert "Attempts" in markdown_report

    print_summary(events, result, parse_stats)
    summary = capsys.readouterr().out
    assert "Log events analyzed            : 2" in summary
    assert "Effective event occurrences    : 5" in summary

    dashboard_events, dashboard_stats, dashboard_result = analyze_for_dashboard(
        FIXTURE, log_type="ssh", year=2026
    )
    dashboard_effective = sum(event["occurrence_count"] for event in dashboard_events)
    assert dashboard_stats["events_parsed"] == 2
    assert dashboard_effective == 5
    hourly_failures = Counter(_attempts_by_hour(dashboard_events).values())
    assert hourly_failures == Counter({5: 1})
    metrics = summarize_dashboard_metrics(
        dashboard_result["alerts"],
        dashboard_result["risk_scores"],
        dashboard_result["incidents"],
    )
    assert metrics["incidents"] == 1
    assert len(dashboard_result["alerts"]) == 2
