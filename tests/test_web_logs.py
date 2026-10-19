"""Combined access-log parsing and defensive web detection tests."""

import ipaddress
from datetime import datetime, timedelta

import pytest

from config import load_config
from detections import analyze_events
from web_detections import (
    detect_web_login_bruteforce,
    detect_web_scanning,
    detect_web_suspicious_user_agent,
)
from web_parser import parse_web_log_file, parse_web_log_line

BASE = datetime(2026, 10, 19, 8, 0)


def request(seconds=0, *, ip="198.51.100.20", path="/login", status=401, agent="Browser/1.0"):
    return {
        "timestamp": BASE + timedelta(seconds=seconds),
        "source_ip": ip,
        "event_type": "web_request",
        "method": "POST",
        "path": path,
        "status": status,
        "bytes": 100,
        "referrer": "-",
        "user_agent": agent,
        "username": None,
    }


def test_combined_parser_fields_timezone_and_stats(tmp_path):
    line = (
        '192.0.2.5 - - [19/Oct/2026:11:00:00 +0300] "POST /login HTTP/1.1" '
        '401 123 "https://example.invalid/" "Browser/1.0"'
    )
    event = parse_web_log_line(line)
    assert event["timestamp"] == datetime(2026, 10, 19, 8, 0)
    assert event["method"] == "POST"
    assert event["path"] == "/login"
    assert event["status"] == 401
    assert event["bytes"] == 123
    assert event["referrer"] == "https://example.invalid/"
    assert event["user_agent"] == "Browser/1.0"

    path = tmp_path / "access.log"
    path.write_text(line + "\n# comment\nnot a combined row\n", encoding="utf-8")
    events, stats = parse_web_log_file(path)
    assert len(events) == 1
    assert stats == {
        "lines_read": 3,
        "events_parsed": 1,
        "lines_ignored": 1,
        "lines_malformed": 1,
    }


def test_web_login_bruteforce_positive_below_window_and_allowlist():
    events = [request(i * 5) for i in range(5)]
    alert = detect_web_login_bruteforce(events)[0]
    assert alert["rule"] == "web_login_bruteforce"
    assert alert["mitre_attack_id"] == "T1110"
    assert alert["path"] == ["/login"]
    assert detect_web_login_bruteforce(events[:4]) == []
    outside = [request(i * 70) for i in range(5)]
    assert detect_web_login_bruteforce(outside) == []
    trusted = [ipaddress.ip_network("198.51.100.0/24")]
    assert detect_web_login_bruteforce(events, allowlist=trusted) == []


def test_web_scanning_positive_below_window_and_allowlist():
    events = [request(i, path=f"/missing-{i}", status=404) for i in range(10)]
    alert = detect_web_scanning(events)[0]
    assert alert["rule"] == "web_scanning"
    assert alert["mitre_attack_id"] == "T1595"
    assert detect_web_scanning(events[:9]) == []
    outside = [request(i * 70, path=f"/missing-{i}", status=404) for i in range(10)]
    assert detect_web_scanning(outside) == []
    trusted = [ipaddress.ip_network("198.51.100.0/24")]
    assert detect_web_scanning(events, allowlist=trusted) == []


def test_suspicious_user_agent_positive_below_window_and_allowlist():
    events = [request(agent="Nmap Scripting Engine")]
    alert = detect_web_suspicious_user_agent(events)[0]
    assert alert["severity"] == "Low"
    assert detect_web_suspicious_user_agent([request(agent="Normal browser")]) == []
    separate = [
        request(0, agent="sqlmap/1"),
        request(70, agent="sqlmap/1"),
    ]
    assert len(detect_web_suspicious_user_agent(separate)) == 2
    trusted = [ipaddress.ip_network("198.51.100.0/24")]
    assert detect_web_suspicious_user_agent(events, allowlist=trusted) == []


def test_web_pipeline_uses_shared_schema_and_html_escapes_user_agent():
    from html_report import render_html_report

    malicious = "<script>alert(1)</script>"
    event = request(agent=malicious)
    config = load_config(None)
    config["web"]["suspicious_user_agents"] = ["<script>"]
    result = analyze_events([event], config=config, log_type="web")
    alert = result["alerts"][0]
    assert all(
        name in alert
        for name in (
            "rule",
            "severity",
            "source_ip",
            "first_seen",
            "last_seen",
            "attempt_count",
            "usernames_targeted",
            "description",
            "mitre_attack_id",
            "mitre_technique_name",
            "recommended_action",
        )
    )
    document = render_html_report(
        [event],
        {
            **result,
            "parse_stats": {"events_parsed": 1, "lines_ignored": 0, "lines_malformed": 0},
            "config_used": config,
        },
    )
    assert malicious not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document


def test_web_config_paths_and_user_agent_values_are_validated(tmp_path):
    config = tmp_path / "invalid.yaml"
    config.write_text("web:\n  login_paths: [login]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="starting with"):
        load_config(config)


def test_web_success_after_failures_is_critical_and_allowlist_suppresses():
    events = [request(i, status=401) for i in range(5)]
    events.append(request(10, status=200))
    result = analyze_events(events, log_type="web")
    alert = next(item for item in result["alerts"] if item["rule"] == "web_success_after_failures")
    assert alert["severity"] == "High"
    assert result["risk_scores"]["198.51.100.20"]["band"] == "Critical"
    trusted = [ipaddress.ip_network("198.51.100.0/24")]
    suppressed = analyze_events(events, allowlist=trusted, log_type="web")
    assert not suppressed["alerts"]
    assert suppressed["alerts_suppressed"] > 0
