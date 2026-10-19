"""
Automated tests for the SSH Detection Engine.

Tests cover:
- Brute-force detection
- Password spraying
- Username enumeration
- Root-login attempts
- Successful login following repeated failures
- Normal authentication activity
- Time-window boundaries
"""

from datetime import datetime, timedelta

import pytest

from detections import (
    detect_brute_force,
    detect_password_spraying,
    detect_root_attempts,
    detect_success_after_failures,
    detect_username_enumeration,
    run_all_detections,
)

BASE_TIME = datetime(2026, 10, 19, 9, 0, 0)


def make_event(
    seconds,
    username="analyst",
    source_ip="192.0.2.10",
    event_type="authentication_failure",
    invalid_user=False,
):
    """Create a synthetic structured authentication event."""

    timestamp = BASE_TIME + timedelta(seconds=seconds)

    return {
        "timestamp": timestamp.isoformat(),
        "hostname": "test-server",
        "process_id": 1000 + seconds,
        "username": username,
        "source_ip": source_ip,
        "source_port": 45000,
        "event_type": event_type,
        "invalid_user": invalid_user,
        "is_root": username == "root",
    }


# ============================================================
# BRUTE-FORCE TESTS
# ============================================================


def test_brute_force_detected():
    events = [make_event(i * 5, source_ip="198.51.100.10") for i in range(5)]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "ssh_brute_force"
    assert alerts[0]["severity"] == "Medium"


def test_brute_force_not_detected_below_threshold():
    events = [make_event(i * 5) for i in range(4)]

    assert detect_brute_force(events) == []


def test_single_attempt_wording_is_singular_when_threshold_is_one():
    failure = make_event(0)
    brute_alert = detect_brute_force([failure], threshold=1)[0]
    root_alert = detect_root_attempts([make_event(0, username="root")], minimum_attempts=1)[0]
    assert "1 failed attempt observed" in brute_alert["description"]
    assert "1 failed attempt targeted root" in root_alert["description"]


def test_brute_force_outside_window():
    events = [
        make_event(0),
        make_event(70),
        make_event(140),
        make_event(210),
        make_event(280),
    ]

    assert detect_brute_force(events) == []


# ============================================================
# PASSWORD-SPRAYING TESTS
# ============================================================


def test_password_spraying_detected():
    usernames = [
        "analyst",
        "admin",
        "developer",
        "backup",
        "guest",
    ]

    events = [
        make_event(
            seconds=i * 10,
            username=username,
            source_ip="198.51.100.20",
        )
        for i, username in enumerate(usernames)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "ssh_password_spraying"
    assert alerts[0]["distinct_usernames"] == 5


def test_password_spraying_not_detected_below_threshold():
    events = [
        make_event(i * 10, username=username)
        for i, username in enumerate(["analyst", "admin", "developer", "backup"])
    ]

    assert detect_password_spraying(events) == []


# ============================================================
# USERNAME-ENUMERATION TESTS
# ============================================================


def test_username_enumeration_detected():
    usernames = [
        "fake1",
        "fake2",
        "fake3",
        "fake4",
    ]

    events = [
        make_event(
            seconds=i * 5,
            username=username,
            source_ip="203.0.113.10",
            invalid_user=True,
        )
        for i, username in enumerate(usernames)
    ]

    alerts = detect_username_enumeration(events)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "ssh_username_enumeration"
    assert alerts[0]["distinct_usernames"] == 4


def test_username_enumeration_requires_invalid_users():
    events = [
        make_event(
            seconds=i * 5,
            username=username,
            invalid_user=False,
        )
        for i, username in enumerate(["analyst", "admin", "developer", "backup"])
    ]

    assert detect_username_enumeration(events) == []


# ============================================================
# ROOT-LOGIN TESTS
# ============================================================


def test_root_login_attempt_detected():
    events = [
        make_event(
            i * 10,
            username="root",
            source_ip="203.0.113.20",
        )
        for i in range(3)
    ]

    alerts = detect_root_attempts(events)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "ssh_root_login_attempt"
    assert alerts[0]["attempt_count"] == 3


def test_successful_root_login_not_counted_as_failed_attempt():
    events = [
        make_event(
            0,
            username="root",
            event_type="authentication_success",
        )
    ]

    assert detect_root_attempts(events) == []


# ============================================================
# SUCCESS-AFTER-FAILURES TESTS
# ============================================================


def test_success_after_repeated_failures_detected():
    source_ip = "198.51.100.60"

    events = [
        make_event(
            i * 5,
            username="admin",
            source_ip=source_ip,
        )
        for i in range(6)
    ]

    events.append(
        make_event(
            35,
            username="admin",
            source_ip=source_ip,
            event_type="authentication_success",
        )
    )

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "ssh_success_after_failures"
    assert alerts[0]["severity"] == "High"


def test_success_without_repeated_failures_not_detected():
    events = [
        make_event(0),
        make_event(
            10,
            event_type="authentication_success",
        ),
    ]

    assert detect_success_after_failures(events) == []


def test_success_from_different_ip_not_linked_to_failures():
    events = [
        make_event(
            i * 5,
            source_ip="198.51.100.60",
        )
        for i in range(6)
    ]

    events.append(
        make_event(
            35,
            source_ip="192.0.2.99",
            event_type="authentication_success",
        )
    )

    assert detect_success_after_failures(events) == []


# ============================================================
# FALSE-POSITIVE AND INPUT VALIDATION TESTS
# ============================================================


def test_normal_successful_logins_produce_no_alerts():
    events = [
        make_event(
            seconds=i * 180,
            username="analyst",
            source_ip="192.0.2.10",
            event_type="authentication_success",
        )
        for i in range(5)
    ]

    assert run_all_detections(events) == []


def test_empty_events_produce_no_alerts():
    assert run_all_detections([]) == []


def test_invalid_brute_force_threshold():
    with pytest.raises(ValueError):
        detect_brute_force([], threshold=0)


def test_invalid_spraying_threshold():
    with pytest.raises(ValueError):
        detect_password_spraying([], username_threshold=0)
