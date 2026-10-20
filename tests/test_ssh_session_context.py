"""Tests for SSH session context and evidence-backed login correlation."""

from datetime import datetime, timedelta

from analyzer import _output_value, render_csv
from config import load_config
from detections import analyze_events
from html_report import render_html_report
from markdown_report import render_markdown_report
from ssh_parser import parse_log_file, parse_log_line

BASE = datetime(2026, 10, 19, 9, 0)


def _auth_event(second, event_type, *, host="edge", pid=412, username="analyst"):
    """Return a synthetic authentication event with a stable sshd identity."""
    return {
        "timestamp": BASE + timedelta(seconds=second),
        "hostname": host,
        "process_id": pid,
        "username": username,
        "source_ip": "192.0.2.70",
        "source_port": 45000,
        "event_type": event_type,
        "invalid_user": False,
        "is_root": username == "root",
        "occurrence_count": 1,
    }


def _session_event(second, *, host="edge", pid=412, username="analyst"):
    """Return synthetic parsed session context without inventing a source IP."""
    return {
        "timestamp": BASE + timedelta(seconds=second),
        "hostname": host,
        "process_id": pid,
        "username": username,
        "source_ip": None,
        "source_port": None,
        "event_type": "session_opened",
        "invalid_user": False,
        "is_root": username == "root",
        "occurrence_count": 1,
    }


def test_parser_retains_session_open_and_close_as_non_auth_records(tmp_path):
    opened = parse_log_line(
        "Oct 19 09:00:10 edge sshd[412]: pam_unix(sshd:session): "
        "session opened for user analyst by (uid=0)",
        year=2026,
    )
    closed = parse_log_line(
        "Oct 19 09:05:10 edge sshd[412]: pam_unix(sshd:session): session closed for user analyst",
        year=2026,
    )

    assert opened["event_type"] == "session_opened"
    assert opened["username"] == "analyst"
    assert opened["source_ip"] is None
    assert opened["process_id"] == 412
    assert closed["event_type"] == "session_closed"

    path = tmp_path / "session.log"
    path.write_text(
        "Oct 19 09:00:00 edge sshd[412]: Accepted publickey for analyst "
        "from 192.0.2.70 port 45000 ssh2\n"
        "Oct 19 09:00:10 edge sshd[412]: pam_unix(sshd:session): "
        "session opened for user analyst by (uid=0)\n",
        encoding="utf-8",
    )
    events, stats = parse_log_file(path, year=2026)

    assert [event["event_type"] for event in events] == [
        "authentication_success",
        "session_opened",
    ]
    assert stats["lines_read"] == stats["events_parsed"] == 2
    assert stats["effective_event_occurrences"] == 2
    assert stats["authentication_successes"] == 1
    assert stats["lines_ignored"] == 0


def test_success_after_failures_includes_matching_post_login_session_context():
    events = [_auth_event(i, "authentication_failure") for i in range(5)]
    events.extend(
        [
            _auth_event(10, "authentication_success"),
            _session_event(15),
        ]
    )

    result = analyze_events(events)
    alert = next(item for item in result["alerts"] if item["rule"] == "ssh_success_after_failures")

    assert alert["attempt_count"] == alert["failed_attempts"] == 5
    assert alert["severity"] == "High"
    assert alert["session_activity"] == [
        {
            "event_type": "session_opened",
            "timestamp": BASE + timedelta(seconds=15),
            "hostname": "edge",
            "process_id": 412,
            "username": "analyst",
        }
    ]
    assert result["incidents"][0]["attempt_count"] == 6
    assert result["incidents"][0]["session_activity"] == alert["session_activity"]
    csv_report = render_csv([alert])
    assert len(csv_report.splitlines()) == 2
    assert "session_activity" in csv_report
    assert (
        _output_value(alert)["session_activity"][0]["timestamp"]
        == (BASE + timedelta(seconds=15)).isoformat()
    )


def test_session_context_requires_same_host_pid_username_and_lookback():
    successes = [_auth_event(10, "authentication_success")]
    sessions = [
        _session_event(11, host="other-host"),
        _session_event(12, pid=999),
        _session_event(13, username="other-user"),
        _session_event(14),
        _session_event(400),
    ]
    events = [_auth_event(i, "authentication_failure") for i in range(5)]
    events.extend([*successes, *sessions])

    result = analyze_events(events)
    alert = next(item for item in result["alerts"] if item["rule"] == "ssh_success_after_failures")

    assert [item["timestamp"] for item in alert["session_activity"]] == [
        BASE + timedelta(seconds=14)
    ]
    assert alert["attempt_count"] == 5


def test_session_context_is_not_attached_without_matching_evidence():
    events = [_auth_event(i, "authentication_failure") for i in range(5)]
    events.extend(
        [
            _auth_event(10, "authentication_success"),
            _session_event(9),
            _session_event(400),
            _session_event(11, pid=None),
        ]
    )

    result = analyze_events(events)
    alert = next(item for item in result["alerts"] if item["rule"] == "ssh_success_after_failures")

    assert "session_activity" not in alert
    assert alert["attempt_count"] == 5


def test_adjacent_success_alerts_preserve_all_linked_session_evidence():
    events = [_auth_event(i, "authentication_failure") for i in range(5)]
    events.extend(
        [
            _auth_event(10, "authentication_success"),
            _session_event(11),
            *[_auth_event(400 + i, "authentication_failure", pid=413) for i in range(5)],
            _auth_event(410, "authentication_success", pid=413),
            _session_event(411, pid=413),
        ]
    )
    config = load_config(None)
    config["alert_merging"]["merge_gap_seconds"] = 600

    result = analyze_events(events, config=config)
    alerts = [item for item in result["alerts"] if item["rule"] == "ssh_success_after_failures"]

    assert len(alerts) == 1
    assert alerts[0]["attempt_count"] == 10
    assert [item["process_id"] for item in alerts[0]["session_activity"]] == [412, 413]


def test_session_context_is_escaped_in_self_contained_html_report():
    username = "<script>alert(1)</script>"
    events = [_auth_event(i, "authentication_failure", username=username) for i in range(5)]
    events.extend(
        [
            _auth_event(10, "authentication_success", username=username),
            _session_event(15, username=username),
        ]
    )
    result = analyze_events(events)
    result.update(
        {
            "parse_stats": {
                "lines_read": 7,
                "events_parsed": 7,
                "effective_event_occurrences": 7,
                "lines_ignored": 0,
                "lines_malformed": 0,
            },
            "alerts_suppressed": 0,
            "config_used": {},
        }
    )

    document = render_html_report(events, result)

    assert username not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    markdown = render_markdown_report(result)
    assert username not in markdown
    assert "&lt;script&gt;alert" in markdown
    assert "&lt;/script&gt;" in markdown
    assert "Session context" in markdown
