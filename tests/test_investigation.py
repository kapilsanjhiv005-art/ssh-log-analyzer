"""Tests for successful-login inventory and conservative session duration linkage."""

from datetime import datetime, timedelta

from investigation import build_successful_login_rows

BASE = datetime(2016, 12, 10, 9, 32, 20)


def _event(second, kind, *, user="analyst", pid=412, source="192.0.2.40", host="edge"):
    return {
        "timestamp": BASE + timedelta(seconds=second),
        "event_type": kind,
        "hostname": host,
        "process_id": pid,
        "username": user,
        "source_ip": source,
        "occurrence_count": 1,
        "_event_id": f"event-{kind}-{second}-{user}",
    }


def test_successful_login_duration_requires_unique_host_pid_user_lifecycle():
    events = [
        _event(-60, "authentication_failure"),
        _event(-10, "authentication_failure"),
        _event(0, "authentication_success"),
        _event(1, "session_opened"),
        _event(766, "session_closed"),
    ]
    alerts = [
        {
            "rule": "ssh_success_after_failures",
            "source_ip": "192.0.2.40",
            "first_seen": BASE - timedelta(seconds=10),
            "last_seen": BASE,
            "attempt_count": 2,
        }
    ]

    rows = build_successful_login_rows(events, alerts, lookback_seconds=300)

    assert len(rows) == 1
    assert rows[0]["timestamp"] == BASE
    assert rows[0]["source_ip"] == "192.0.2.40"
    assert rows[0]["username"] == "analyst"
    assert rows[0]["hostname"] == "edge"
    assert rows[0]["process_id"] == 412
    assert rows[0]["session_identifier"] is None
    assert rows[0]["duration_seconds"] == 766
    assert rows[0]["related_failures"] == 2
    assert rows[0]["related_alert_rules"] == ["ssh_success_after_failures"]
    assert "unique host/pid/username" in rows[0]["correlation_status"].casefold()
    assert "estimated" in rows[0]["correlation_status"].casefold()
    assert "estimated" in rows[0]["duration_basis"].casefold()


def test_successful_login_keeps_missing_source_and_ambiguous_duration_unknown():
    missing_source = [
        _event(0, "authentication_success", source=None),
        _event(1, "session_opened", source=None),
        _event(60, "session_closed", source=None),
    ]
    rows = build_successful_login_rows(missing_source, [], lookback_seconds=300)

    assert rows[0]["source_ip"] is None
    assert rows[0]["related_failures"] is None
    assert rows[0]["duration_seconds"] == 60

    ambiguous = missing_source + [_event(70, "session_closed", source=None)]
    rows = build_successful_login_rows(ambiguous, [], lookback_seconds=300)
    assert rows[0]["duration_seconds"] is None
    assert "ambiguous" in rows[0]["correlation_status"].casefold()


def test_successful_login_session_linkage_does_not_cross_users_or_pids():
    events = [
        _event(0, "authentication_success", user="alice", pid=1),
        _event(1, "session_opened", user="alice", pid=1),
        _event(0, "authentication_success", user="bob", pid=2),
        _event(2, "session_opened", user="bob", pid=2),
        _event(30, "session_closed", user="alice", pid=1),
        _event(40, "session_closed", user="bob", pid=2),
    ]

    rows = build_successful_login_rows(events, [], lookback_seconds=300)

    assert {row["username"]: row["duration_seconds"] for row in rows} == {
        "alice": 30,
        "bob": 40,
    }
