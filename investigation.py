"""Evidence-backed summaries of successful SSH authentications."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from event_accounting import event_occurrences


def _timestamp(value: Any) -> datetime | None:
    """Return a comparable naive-UTC timestamp for parser-produced values."""
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, str):
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if stamp.tzinfo is not None:
        return stamp.astimezone(timezone.utc).replace(tzinfo=None)
    return stamp


def _context_key(event: dict[str, Any]) -> tuple[str, int, str] | None:
    """Return a host/PID/user key only when all three fields are present."""
    host = event.get("hostname")
    pid = event.get("process_id")
    username = event.get("username")
    if not isinstance(host, str) or not host or not isinstance(pid, int) or isinstance(pid, bool):
        return None
    if not isinstance(username, str) or not username:
        return None
    return host, pid, username


def build_successful_login_rows(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    *,
    lookback_seconds: int = 300,
) -> list[dict[str, Any]]:
    """Build a login inventory with only uniquely linkable session durations.

    Duration is measured from the successful authentication to session close.
    A lifecycle is considered unique only when exactly one successful outcome,
    one session-open, and one session-close share host, daemon PID, and username
    and occur in chronological order. This deliberately omits ambiguous links.
    """
    if lookback_seconds < 0:
        raise ValueError("lookback_seconds cannot be negative")
    context_events: dict[tuple[str, int, str], dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: {"authentication_success": [], "session_opened": [], "session_closed": []}
    )
    successes = []
    failures_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        event_type = event.get("event_type")
        key = _context_key(event)
        if key and event_type in {"authentication_success", "session_opened", "session_closed"}:
            context_events[key][event_type].append(event)
        if event_type == "authentication_success":
            successes.append(event)
        elif event_type == "authentication_failure" and event.get("source_ip"):
            failures_by_source[str(event["source_ip"])].append(event)

    rows = []
    for success in sorted(
        successes, key=lambda event: _timestamp(event.get("timestamp")) or datetime.min
    ):
        stamp = _timestamp(success.get("timestamp"))
        source_ip = success.get("source_ip")
        key = _context_key(success)
        lifecycle = context_events.get(key, {}) if key else {}
        outcomes = lifecycle.get("authentication_success", [])
        opened = lifecycle.get("session_opened", [])
        closed = lifecycle.get("session_closed", [])
        duration_seconds = None
        if key is None:
            correlation_status = "Unavailable: host, daemon PID, or username is missing."
        elif (
            len(outcomes) == 1
            and event_occurrences(outcomes[0]) == 1
            and len(opened) == 1
            and len(closed) == 1
        ):
            open_time = _timestamp(opened[0].get("timestamp"))
            close_time = _timestamp(closed[0].get("timestamp"))
            success_time = _timestamp(outcomes[0].get("timestamp"))
            if (
                success_time is not None
                and open_time is not None
                and close_time is not None
                and success_time <= open_time <= close_time
            ):
                duration_seconds = int((close_time - success_time).total_seconds())
                correlation_status = "Estimated duration from a unique host/PID/username lifecycle match; no session ID exists in the log."
            else:
                correlation_status = (
                    "Unavailable: lifecycle timestamps are missing or out of order."
                )
        elif not closed:
            correlation_status = "Unavailable: no matching session-close record was parsed."
        else:
            correlation_status = "Ambiguous host/PID/username lifecycle; duration omitted."

        if source_ip and stamp is not None:
            window_start = stamp - timedelta(seconds=lookback_seconds)
            related_failures = sum(
                event_occurrences(event)
                for event in failures_by_source.get(str(source_ip), [])
                if (failure_time := _timestamp(event.get("timestamp"))) is not None
                and window_start <= failure_time < stamp
            )
        else:
            related_failures = None

        related_rules = sorted(
            {
                str(alert.get("rule"))
                for alert in alerts
                if source_ip
                and alert.get("source_ip") == source_ip
                and stamp is not None
                and (first := _timestamp(alert.get("first_seen"))) is not None
                and (last := _timestamp(alert.get("last_seen"))) is not None
                and first <= stamp <= last
            }
        )
        limitations = [
            "A successful authentication does not by itself establish malicious activity or compromise."
        ]
        if success.get("process_id") is None or not success.get("hostname"):
            limitations.append("The log lacks a stable host/daemon-PID correlation key.")
        if not source_ip:
            limitations.append("No source IP is attributed to this successful authentication.")
        if duration_seconds is None:
            limitations.append(correlation_status)
        rows.append(
            {
                "timestamp": stamp,
                "source_ip": source_ip,
                "username": success.get("username"),
                "hostname": success.get("hostname"),
                "process_id": success.get("process_id"),
                "session_identifier": None,
                "session_identifier_note": "Not present in supported log records.",
                "duration_seconds": duration_seconds,
                "duration_basis": (
                    "Estimated elapsed interval from successful authentication to the uniquely matched session-close record; no session ID exists in the log."
                    if duration_seconds is not None
                    else "Unavailable: a unique host/PID/username session-close match was not established."
                ),
                "related_failures": related_failures,
                "failure_lookback_seconds": lookback_seconds,
                "related_alert_rules": related_rules,
                "correlation_status": correlation_status,
                "classification": "Successful authentication observed",
                "data_quality_limitations": limitations,
                "occurrence_count": event_occurrences(success),
                "event_id": success.get("_event_id"),
            }
        )
    return rows
