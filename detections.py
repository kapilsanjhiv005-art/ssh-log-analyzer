"""Explainable SSH detections, alert aggregation, correlation, and risk scoring."""

from __future__ import annotations

import math
from bisect import bisect_left, bisect_right
from collections import defaultdict, deque
from datetime import datetime, time, timedelta
from typing import Any

from config import DEFAULT_CONFIG, is_allowlisted, is_trusted_source, load_config
from event_accounting import event_occurrences

BRUTE_FORCE_THRESHOLD = 5
PASSWORD_SPRAY_THRESHOLD = 5
USERNAME_ENUMERATION_THRESHOLD = 4
SUCCESS_FAILURE_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(seconds=60)
SUCCESS_LOOKBACK = timedelta(minutes=5)

# Transparent risk-score weights. Volume grows logarithmically and is capped.
RISK_PER_RULE = 10  # Points per distinct alert rule.
RISK_RULE_CAP = 40  # Maximum contribution from alert-rule breadth.
RISK_VOLUME_WEIGHT = 20  # Maximum multiplier for the log-scaled failure volume.
RISK_VOLUME_REFERENCE = 1000  # Failure count where the log-scaled volume reaches its cap.
RISK_VOLUME_CAP = 20  # Maximum contribution from failure volume.
RISK_ROOT_TARGETING = 15  # Additional points when failed attempts target root.
RISK_SUCCESS_AFTER_FAILURES = 30  # Additional points for confirmed success after failures.
RISK_CONFIRMED_SUCCESS_FLOOR = 75  # Critical floor reserved for confirmed success-after-failures.
RISK_UNCONFIRMED_CAP = 74  # Prevent Critical scores without a confirmed success signal.
SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
RISK_BANDS = ((75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low"))

MITRE_MAPPING_NOTES = {
    "ssh_password_spraying": (
        "No technique assigned: distinct failed usernames do not establish that one password "
        "was tried across accounts."
    ),
    "ssh_username_enumeration": (
        "No technique assigned: invalid-user attempts show probing behavior, not confirmed "
        "account discovery."
    ),
    "web_login_bruteforce": (
        "No technique assigned: repeated 401/403 responses on a configured login path do not "
        "prove authentication attempts."
    ),
    "web_success_after_failures": (
        "No technique assigned: a 2xx response after 401/403 responses does not confirm "
        "authentication or a valid account."
    ),
}

RULE_INFO = {
    "ssh_brute_force": (
        "T1110.001",
        "Password Guessing",
        "Block the source IP at the firewall and review logs for other hosts",
    ),
    "ssh_low_and_slow_bruteforce": (
        "T1110.001",
        "Password Guessing",
        "Review the source activity over the longer window and tune a local allowlist if approved",
    ),
    "ssh_password_spraying": (
        None,
        None,
        "Review the source activity across accounts; do not infer a shared password",
    ),
    "ssh_username_enumeration": (
        None,
        None,
        "Review invalid-user probes; the observed records do not confirm account discovery",
    ),
    "ssh_root_login_attempt": (
        "T1110",
        "Brute Force",
        "Block the source IP and review privileged login policy",
    ),
    "ssh_success_after_failures": (
        "T1078",
        "Valid Accounts",
        "Force a password reset and review session activity for this account",
    ),
    "ssh_distributed_bruteforce": (
        "T1110",
        "Brute Force",
        "Review source hosts and protect the targeted account",
    ),
    "ssh_off_hours_login": (
        "T1078",
        "Valid Accounts",
        "Verify the login with the account owner and review session activity",
    ),
    "ssh_new_source_ip_login": (
        "T1078",
        "Valid Accounts",
        "Verify the new source IP and review session activity",
    ),
    "web_login_bruteforce": (
        None,
        None,
        "Review the source IP and verify whether the responses correspond to authentication attempts",
    ),
    "web_scanning": (
        "T1595",
        "Active Scanning",
        "Review requests and block abusive sources at the web perimeter",
    ),
    "web_suspicious_user_agent": (
        "T1595",
        "Active Scanning",
        "Review the request sequence and source IP",
    ),
    "web_success_after_failures": (
        None,
        None,
        "Review application or identity-provider logs to confirm whether authentication succeeded",
    ),
}


def risk_band(score: int) -> str:
    """Map an integer score in the 0-100 range to its display band."""
    if not 0 <= score <= 100:
        raise ValueError("risk score must be between 0 and 100")
    return next(label for minimum, label in RISK_BANDS if score >= minimum)


def get_event_time(event: dict[str, Any]) -> datetime:
    """Return event timestamp as a datetime for comparisons."""
    value = event["timestamp"]
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def _base_alert(
    rule: str,
    severity: str,
    source_ip: str | None,
    records: list[dict[str, Any]],
    description: str,
    attempt_count: int | None = None,
    **details: Any,
) -> dict[str, Any]:
    """Create the common alert schema while retaining legacy aliases."""
    mitre_id, technique_name, action = RULE_INFO[rule]
    times = [get_event_time(record) for record in records]
    usernames = sorted({record["username"] for record in records if record.get("username")})
    count = attempt_count if attempt_count is not None else _event_count(records)
    alert = {
        "rule": rule,
        "severity": severity,
        "base_severity": severity,
        "source_ip": source_ip,
        "first_seen": min(times) if times else None,
        "last_seen": max(times) if times else None,
        "attempt_count": count,
        "usernames_targeted": usernames,
        "authentication_methods": sorted(
            {
                record["authentication_method"]
                for record in records
                if record.get("authentication_method")
            }
        ),
        "description": description,
        "mitre_attack_id": mitre_id,
        "mitre_technique_name": technique_name,
        "recommended_action": action,
        # Compatibility aliases used by the original tests and report consumers.
        "attack_technique": mitre_id,
        "attempts": count,
        "_merge_event_ids": [_event_identity(record) for record in records],
        "_incident_event_counts": {
            _event_identity(record): _event_occurrences(record) for record in records
        },
        "_merge_attempt_ids": [
            _event_identity(record)
            for record in records
            if rule not in {"ssh_success_after_failures", "web_success_after_failures"}
            or _is_failure(record)
        ],
        "_merge_attempt_counts": {
            _event_identity(record): _event_occurrences(record)
            for record in records
            if rule not in {"ssh_success_after_failures", "web_success_after_failures"}
            or _is_failure(record)
        },
        "window_seconds": details.get("window_seconds", 60),
        **details,
    }
    if rule in MITRE_MAPPING_NOTES:
        alert["mitre_mapping_note"] = MITRE_MAPPING_NOTES[rule]
    supporting_evidence = {
        evidence.get("event_id"): evidence
        for record in records
        for evidence in record.get("supporting_evidence", [])
        if evidence.get("event_id") is not None
    }
    if supporting_evidence:
        alert["supporting_evidence"] = sorted(
            supporting_evidence.values(), key=lambda item: item.get("timestamp", datetime.min)
        )
    return alert


def _event_occurrences(event: dict[str, Any]) -> int:
    """Return the represented occurrence count, defaulting legacy events to one."""
    return event_occurrences(event)


def _event_count(records: list[dict[str, Any]]) -> int:
    """Sum represented occurrences without expanding repeated log messages."""
    return sum(_event_occurrences(record) for record in records)


def _event_identity(event: dict[str, Any]) -> Any:
    """Return a stable parser identity or an in-process identity for test events."""
    return event.get("_event_id", id(event))


def _count_word(count: int, singular: str = "attempt") -> str:
    """Format an event count with correct singular/plural wording."""
    return f"{count} {singular if count == 1 else singular + 's'}"


def merge_adjacent_alerts(
    alerts: list[dict[str, Any]],
    merge_gap_seconds: int | None = None,
) -> list[dict[str, Any]]:
    """Merge alerts for the same rule/source when their windows touch or nearly touch.

    When no explicit gap is configured, each rule uses its own detection window.
    Event identities are unioned so overlapping windows do not inflate attempts.
    """
    grouped: dict[tuple[str, str | None], list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        grouped[(alert["rule"], alert.get("source_ip"))].append(alert)
    merged: list[dict[str, Any]] = []
    for (rule, _ip), group in grouped.items():
        group.sort(key=lambda item: item.get("first_seen") or datetime.min)
        clusters: list[list[dict[str, Any]]] = []
        cluster_last_seen: list[datetime] = []
        for alert in group:
            gap = merge_gap_seconds
            if gap is None:
                gap = int(alert.get("window_seconds", 60))
            if (
                not clusters
                or alert.get("first_seen") is None
                or alert["first_seen"] > cluster_last_seen[-1] + timedelta(seconds=gap)
            ):
                clusters.append([alert])
                cluster_last_seen.append(alert["last_seen"])
            else:
                clusters[-1].append(alert)
                cluster_last_seen[-1] = max(cluster_last_seen[-1], alert["last_seen"])
        for cluster in clusters:
            if len(cluster) == 1:
                result = dict(cluster[0])
            else:
                result = dict(cluster[0])
                result["first_seen"] = min(
                    item["first_seen"] for item in cluster if item.get("first_seen")
                )
                result["last_seen"] = max(
                    item["last_seen"] for item in cluster if item.get("last_seen")
                )
                event_ids = set().union(
                    *(set(item.get("_merge_event_ids", [])) for item in cluster)
                )
                attempt_ids = set().union(
                    *(set(item.get("_merge_attempt_ids", [])) for item in cluster)
                )
                attempt_counts: dict[Any, int] = {}
                for item in cluster:
                    for identity, count in item.get("_merge_attempt_counts", {}).items():
                        attempt_counts[identity] = max(attempt_counts.get(identity, 0), count)
                result["attempt_count"] = (
                    sum(attempt_counts.values())
                    if attempt_counts
                    else len(attempt_ids)
                    if attempt_ids
                    else sum(item.get("attempt_count", 0) for item in cluster)
                )
                result["attempts"] = result["attempt_count"]
                result["unique_event_count"] = len(event_ids)
                result["merged_alert_count"] = sum(
                    item.get("merged_alert_count", 1) for item in cluster
                )
                result["usernames_targeted"] = sorted(
                    set().union(*(set(item.get("usernames_targeted", [])) for item in cluster))
                )
                session_activity = {}
                for item in cluster:
                    for session in item.get("session_activity", []):
                        identity = (
                            session.get("event_type"),
                            session.get("timestamp"),
                            session.get("hostname"),
                            session.get("process_id"),
                            session.get("username"),
                        )
                        session_activity[identity] = session
                if session_activity:
                    result["session_activity"] = sorted(
                        session_activity.values(), key=lambda session: session["timestamp"]
                    )
                supporting_evidence = {
                    evidence.get("event_id"): evidence
                    for item in cluster
                    for evidence in item.get("supporting_evidence", [])
                    if evidence.get("event_id") is not None
                }
                if supporting_evidence:
                    result["supporting_evidence"] = sorted(
                        supporting_evidence.values(),
                        key=lambda item: item.get("timestamp", datetime.min),
                    )
                for field in (
                    "paths",
                    "statuses",
                    "user_agents",
                    "source_ips",
                    "authentication_methods",
                ):
                    values = [value for item in cluster for value in item.get(field, [])]
                    if values:
                        result[field] = sorted(set(values))
                if "path" in result and isinstance(result["path"], list):
                    result["path"] = result.get("paths", result["path"])
                if "user_agent" in result and isinstance(result["user_agent"], list):
                    result["user_agent"] = result.get("user_agents", result["user_agent"])
                result["description"] = (
                    f"{_count_word(result['attempt_count'])} aggregated across {len(cluster)} adjacent alert windows."
                )
            result["_merge_event_ids"] = list(
                set().union(*(set(item.get("_merge_event_ids", [])) for item in cluster))
            )
            result["_merge_attempt_ids"] = list(
                set().union(*(set(item.get("_merge_attempt_ids", [])) for item in cluster))
            )
            for field in ("_incident_event_counts", "_merge_attempt_counts"):
                counts: dict[Any, int] = {}
                for item in cluster:
                    for identity, count in item.get(field, {}).items():
                        counts[identity] = max(counts.get(identity, 0), count)
                result[field] = counts
            merged.append(result)
    merged.sort(
        key=lambda item: (
            item.get("first_seen") or datetime.min,
            item["rule"],
            item.get("source_ip") or "",
        )
    )
    return merged


def create_alert(
    rule: str,
    severity: str,
    source_ip: str | None,
    description: str,
    attack_technique: str | None = None,
    **details: Any,
) -> dict[str, Any]:
    """Compatibility helper for callers that used the former alert factory."""
    records = details.pop("_records", [])
    alert = _base_alert(rule, severity, source_ip, records, description, **details)
    if attack_technique:
        alert["attack_technique"] = attack_technique
    return alert


def group_events_by_ip(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group events by source IP and sort each group chronologically."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("source_ip"):
            grouped[event["source_ip"]].append(event)
    for values in grouped.values():
        values.sort(key=get_event_time)
    return grouped


def _settings(config: dict[str, Any] | None) -> dict[str, Any]:
    """Return validated configuration, accepting partial test overrides."""
    if config is None:
        return load_config(None)
    # Overlay partial configs through the standard loader/validator shape.
    merged = {section: dict(values) for section, values in DEFAULT_CONFIG.items()}
    for section, values in config.items():
        if section in merged:
            merged[section].update(values)
    from config import validate_config

    return validate_config(merged)


def _clusters(records: list[dict[str, Any]], window: timedelta) -> list[list[dict[str, Any]]]:
    """Create non-overlapping anchored time windows from sorted records."""
    clusters: list[list[dict[str, Any]]] = []
    for record in sorted(records, key=get_event_time):
        if not clusters or get_event_time(record) - get_event_time(clusters[-1][0]) > window:
            clusters.append([record])
        else:
            clusters[-1].append(record)
    return clusters


def _activity_waves(records: list[dict[str, Any]], window: timedelta) -> list[list[dict[str, Any]]]:
    """Group same-source records until an inactivity gap exceeds the rule window."""
    waves: list[list[dict[str, Any]]] = []
    for record in sorted(records, key=get_event_time):
        if not waves or get_event_time(record) - get_event_time(waves[-1][-1]) > window:
            waves.append([record])
        else:
            waves[-1].append(record)
    return waves


def _is_failure(event: dict[str, Any]) -> bool:
    if event.get("event_type") == "authentication_failure":
        # Keep supported failures, but do not treat a "none" method probe as guessing.
        return event.get("authentication_method") != "none"
    return event.get("event_type") == "web_request" and event.get("status") in (401, 403, 404)


def detect_brute_force(
    events: list[dict[str, Any]],
    threshold: int = BRUTE_FORCE_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect same-source failure waves with a qualifying trailing-window burst.

    Each wave continues while adjacent failures are no more than ``window`` apart.
    A wave is emitted only when at least ``threshold`` weighted occurrences fit
    in one inclusive trailing window; all unique records in that wave are retained.
    """
    if threshold < 1 or window < timedelta(0):
        raise ValueError("threshold must be positive and window cannot be negative")
    grouped = group_events_by_ip(
        [e for e in events if _is_failure(e) and not is_allowlisted(e.get("source_ip"), allowlist)]
    )
    alerts = []
    for ip, failures in grouped.items():
        for wave in _activity_waves(failures, window):
            peak = _maximum_window_event_count(wave, window)
            if peak >= threshold:
                attempts = _event_count(wave)
                alerts.append(
                    _base_alert(
                        "ssh_brute_force",
                        "Medium",
                        ip,
                        wave,
                        f"{_count_word(attempts, 'failed attempt')} observed in one activity wave; "
                        f"at least {threshold} occurred within an inclusive trailing "
                        f"{int(window.total_seconds())}-second window.",
                        attempt_count=attempts,
                        window_seconds=int(window.total_seconds()),
                        qualifying_window_attempts=peak,
                    )
                )
    return alerts


def _maximum_window_event_count(events: list[dict[str, Any]], window: timedelta) -> int:
    """Return the maximum weighted event count in any trailing time window."""
    left = 0
    active_count = 0
    maximum = 0
    for right, event in enumerate(events):
        current = get_event_time(event)
        active_count += _event_occurrences(event)
        while current - get_event_time(events[left]) > window:
            active_count -= _event_occurrences(events[left])
            left += 1
        maximum = max(maximum, active_count)
    return maximum


def detect_low_and_slow_bruteforce(
    events: list[dict[str, Any]],
    threshold: int = 20,
    window: timedelta = timedelta(hours=24),
    short_threshold: int = BRUTE_FORCE_THRESHOLD,
    short_window: timedelta = DEFAULT_WINDOW,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect sustained SSH failures that stay below the short brute-force limit.

    Long windows are anchored at their first event, matching the existing
    detection-window convention. Repeated records retain their occurrence weight.
    """
    if threshold < 1 or short_threshold < 1:
        raise ValueError("threshold and short_threshold must be positive")
    if window <= short_window or short_window < timedelta(0):
        raise ValueError("window must be greater than a non-negative short_window")
    failures = [
        event
        for event in events
        if event.get("event_type") == "authentication_failure"
        and not is_allowlisted(event.get("source_ip"), allowlist)
    ]
    alerts = []
    for source_ip, source_events in group_events_by_ip(failures).items():
        for cluster in _clusters(source_events, window):
            attempts = _event_count(cluster)
            if attempts < threshold:
                continue
            short_peak = _maximum_window_event_count(cluster, short_window)
            if short_peak >= short_threshold:
                continue
            alerts.append(
                _base_alert(
                    "ssh_low_and_slow_bruteforce",
                    "Medium",
                    source_ip,
                    cluster,
                    f"{_count_word(attempts, 'failed attempt')} observed across "
                    f"{int(window.total_seconds())} seconds while no "
                    f"{int(short_window.total_seconds())}-second window reached "
                    f"the {short_threshold}-attempt brute-force threshold.",
                    attempt_count=attempts,
                    window_seconds=int(window.total_seconds()),
                    short_window_seconds=int(short_window.total_seconds()),
                    short_window_attempts=short_peak,
                    short_window_threshold=short_threshold,
                )
            )
    return alerts


def detect_password_spraying(
    events: list[dict[str, Any]],
    username_threshold: int = PASSWORD_SPRAY_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect many distinct account names attempted by one source in a window."""
    if username_threshold < 1 or window < timedelta(0):
        raise ValueError("username_threshold must be positive and window cannot be negative")
    grouped = group_events_by_ip(
        [e for e in events if _is_failure(e) and not is_allowlisted(e.get("source_ip"), allowlist)]
    )
    alerts = []
    for ip, failures in grouped.items():
        for cluster in _clusters(failures, window):
            usernames = sorted({e.get("username") for e in cluster if e.get("username")})
            if len(usernames) >= username_threshold:
                alerts.append(
                    _base_alert(
                        "ssh_password_spraying",
                        "Medium",
                        ip,
                        cluster,
                        f"Observed {_count_word(_event_count(cluster), 'failed attempt')} across "
                        f"{_count_word(len(usernames), 'distinct username')} within "
                        f"{int(window.total_seconds())} seconds: multi-account guessing; "
                        "the log does not show whether a password was shared.",
                        attempt_count=_event_count(cluster),
                        distinct_usernames=len(usernames),
                        usernames=usernames,
                        window_seconds=int(window.total_seconds()),
                    )
                )
    return alerts


def detect_username_enumeration(
    events: list[dict[str, Any]],
    threshold: int = USERNAME_ENUMERATION_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect distinct invalid account names attempted by one source."""
    if threshold < 1 or window < timedelta(0):
        raise ValueError("threshold must be positive and window cannot be negative")
    invalids = [
        e
        for e in events
        if _is_failure(e)
        and e.get("invalid_user")
        and not is_allowlisted(e.get("source_ip"), allowlist)
    ]
    alerts = []
    for ip, failures in group_events_by_ip(invalids).items():
        for cluster in _clusters(failures, window):
            usernames = sorted({e.get("username") for e in cluster if e.get("username")})
            if len(usernames) >= threshold:
                alerts.append(
                    _base_alert(
                        "ssh_username_enumeration",
                        "Medium",
                        ip,
                        cluster,
                        f"Observed {_count_word(len(usernames), 'distinct invalid username')} "
                        f"attempted within {int(window.total_seconds())} seconds: invalid-user "
                        "probing; account discovery is not confirmed.",
                        distinct_usernames=len(usernames),
                        usernames=usernames,
                        window_seconds=int(window.total_seconds()),
                    )
                )
    return alerts


def detect_root_attempts(
    events: list[dict[str, Any]],
    window: timedelta = DEFAULT_WINDOW,
    minimum_attempts: int = 3,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Aggregate failed root-targeting attempts by IP and configured window."""
    if minimum_attempts < 1 or window < timedelta(0):
        raise ValueError("minimum_attempts must be positive and window cannot be negative")
    root_failures = [
        e
        for e in events
        if _is_failure(e)
        and e.get("username") == "root"
        and not is_allowlisted(e.get("source_ip"), allowlist)
    ]
    alerts = []
    for ip, failures in group_events_by_ip(root_failures).items():
        for cluster in _clusters(failures, window):
            if _event_count(cluster) < minimum_attempts:
                continue
            alerts.append(
                _base_alert(
                    "ssh_root_login_attempt",
                    "Low",
                    ip,
                    cluster,
                    f"{_count_word(_event_count(cluster), 'failed attempt')} targeted root.",
                    attempt_count=_event_count(cluster),
                    username="root",
                    username_target_count=1,
                    window_seconds=int(window.total_seconds()),
                )
            )
    return alerts


def detect_success_after_failures(
    events: list[dict[str, Any]],
    failure_threshold: int = SUCCESS_FAILURE_THRESHOLD,
    lookback: timedelta = SUCCESS_LOOKBACK,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect and aggregate successful logins after enough recent failures."""
    if failure_threshold < 1 or lookback < timedelta(0):
        raise ValueError("failure_threshold must be positive and lookback cannot be negative")
    sessions_by_context: dict[tuple[str, int, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("event_type") != "session_opened":
            continue
        hostname = event.get("hostname")
        process_id = event.get("process_id")
        username = event.get("username")
        if hostname and process_id is not None and username:
            sessions_by_context[(hostname, process_id, username)].append(event)
    session_times_by_context = {}
    for key, sessions in sessions_by_context.items():
        sessions.sort(key=get_event_time)
        session_times_by_context[key] = [get_event_time(event) for event in sessions]

    alerts = []
    for ip, group in group_events_by_ip(events).items():
        if is_allowlisted(ip, allowlist):
            continue
        failures: deque[dict[str, Any]] = deque()
        active_failure_count = 0
        all_failures: list[dict[str, Any]] = []
        qualifying_successes: list[dict[str, Any]] = []
        for event in group:
            current = get_event_time(event)
            while failures and current - get_event_time(failures[0]) > lookback:
                active_failure_count -= _event_occurrences(failures.popleft())
            if _is_failure(event):
                failures.append(event)
                active_failure_count += _event_occurrences(event)
                all_failures.append(event)
            elif (
                event.get("event_type") == "authentication_success"
                and active_failure_count >= failure_threshold
            ):
                qualifying_successes.append(event)
        failure_times = [get_event_time(event) for event in all_failures]
        for success_cluster in _clusters(qualifying_successes, lookback):
            first_success = get_event_time(success_cluster[0])
            last_success = get_event_time(success_cluster[-1])
            left = bisect_left(failure_times, first_success - lookback)
            right = bisect_right(failure_times, last_success)
            records = sorted(
                [*all_failures[left:right], *success_cluster],
                key=get_event_time,
            )
            failures_in_window = all_failures[left:right]
            usernames = {e.get("username") for e in success_cluster if e.get("username")}
            session_activity: dict[Any, dict[str, Any]] = {}
            for success_event in success_cluster:
                context = (
                    success_event.get("hostname"),
                    success_event.get("process_id"),
                    success_event.get("username"),
                )
                if not all(context):
                    continue
                sessions = sessions_by_context.get(context, [])
                session_times = session_times_by_context.get(context, [])
                success_time = get_event_time(success_event)
                session_start = bisect_left(session_times, success_time)
                session_end = bisect_right(session_times, success_time + lookback)
                for session in sessions[session_start:session_end]:
                    session_activity[_event_identity(session)] = {
                        "event_type": "session_opened",
                        "timestamp": get_event_time(session),
                        "hostname": session["hostname"],
                        "process_id": session["process_id"],
                        "username": session["username"],
                    }
            alert = _base_alert(
                "ssh_success_after_failures",
                "High",
                ip,
                records,
                "Successful SSH authentication followed repeated failures from the same source IP. Investigate for possible account compromise.",
                attempt_count=_event_count(failures_in_window),
                failed_attempts=_event_count(failures_in_window),
                username=sorted(usernames)[0] if usernames else None,
                window_seconds=int(lookback.total_seconds()),
                **(
                    {
                        "session_activity": sorted(
                            session_activity.values(), key=lambda item: item["timestamp"]
                        )
                    }
                    if session_activity
                    else {}
                ),
            )
            alerts.append(alert)
    return alerts


def detect_distributed_bruteforce(
    events: list[dict[str, Any]],
    ip_threshold: int = 5,
    window: timedelta = timedelta(seconds=120),
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect multiple distinct IPs failing against one username in a window."""
    if ip_threshold < 1 or window < timedelta(0):
        raise ValueError("ip_threshold must be positive and window cannot be negative")
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        user = event.get("username")
        if _is_failure(event) and user and not is_allowlisted(event.get("source_ip"), allowlist):
            by_user[user].append(event)
    alerts = []
    for username, failures in by_user.items():
        for cluster in _clusters(failures, window):
            ips = sorted({e["source_ip"] for e in cluster if e.get("source_ip")})
            if len(ips) >= ip_threshold:
                alert = _base_alert(
                    "ssh_distributed_bruteforce",
                    "High",
                    None,
                    cluster,
                    f"{_count_word(len(ips), 'source IP')} failed authentication against the same username within {int(window.total_seconds())} seconds.",
                    attempt_count=_event_count(cluster),
                    target_username=username,
                    source_ips=ips,
                    distinct_source_ips=len(ips),
                    usernames_targeted=[username],
                )
                alerts.append(alert)
    return alerts


def detect_off_hours_login(
    events: list[dict[str, Any]],
    business_start: str = "08:00",
    business_end: str = "19:00",
    lookback: timedelta = SUCCESS_LOOKBACK,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect successful logins outside business hours, raising severity after failures."""
    start_hour, start_minute = map(int, business_start.split(":"))
    end_hour, end_minute = map(int, business_end.split(":"))
    start = time(start_hour, start_minute)
    end = time(end_hour, end_minute)
    alerts = []
    for ip, group in group_events_by_ip(events).items():
        if is_allowlisted(ip, allowlist):
            continue
        failures: deque[datetime] = deque()
        off_hours: list[dict[str, Any]] = []
        recent_failure_at_login: dict[int, bool] = {}
        for event in group:
            current = get_event_time(event)
            while failures and current - failures[0] > lookback:
                failures.popleft()
            if _is_failure(event):
                failures.append(current)
                continue
            if event.get("event_type") != "authentication_success":
                continue
            login_time = current.time()
            in_business_hours = (
                start <= login_time < end
                if start < end
                else login_time >= start or login_time < end
            )
            if in_business_hours:
                continue
            off_hours.append(event)
            recent_failure_at_login[id(event)] = bool(failures)
        for cluster in _clusters(off_hours, timedelta(days=1)):
            recent_failure = any(recent_failure_at_login[id(item)] for item in cluster)
            alert = _base_alert(
                "ssh_off_hours_login",
                "Medium" if recent_failure else "Low",
                ip,
                cluster,
                f"{_count_word(len(cluster), 'successful SSH login')} occurred outside configured business hours ({business_start}-{business_end}).",
                recent_failures=recent_failure,
                window_seconds=86400,
            )
            alerts.append(alert)
    return alerts


def detect_new_source_ip_login(
    events: list[dict[str, Any]],
    allowlist: list[Any] | None = None,
    trusted_local_sources: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Detect successful logins outside allowlisted and trusted-local networks."""
    if allowlist is None:
        return []
    if trusted_local_sources is None:
        trusted_local_sources = DEFAULT_CONFIG["new_source_ip"]["trusted_local_sources"]
    successes = [
        e
        for e in events
        if e.get("event_type") == "authentication_success"
        and not is_trusted_source(e.get("source_ip"), allowlist, trusted_local_sources)
    ]
    alerts = []
    for ip, group in group_events_by_ip(successes).items():
        for cluster in _clusters(group, timedelta(days=1)):
            alerts.append(
                _base_alert(
                    "ssh_new_source_ip_login",
                    "Low",
                    ip,
                    cluster,
                    "Successful SSH login originated from an IP outside the known-good allowlist.",
                    window_seconds=86400,
                )
            )
    return alerts


def _detect_all(
    events: list[dict[str, Any]],
    config: dict[str, Any] | None,
    allowlist: list[Any] | None,
    log_type: str = "ssh",
) -> tuple[list[dict[str, Any]], int]:
    settings = _settings(config)
    brute = settings["brute_force"]
    spray = settings["password_spraying"]
    enumeration = settings["username_enumeration"]
    distributed = settings["distributed_bruteforce"]
    success = settings["success_after_failures"]
    off_hours = settings["off_hours"]
    candidates = []
    if log_type == "ssh":
        candidates += detect_brute_force(
            events, brute["threshold"], timedelta(seconds=brute["window_seconds"])
        )
        low_and_slow = settings["low_and_slow"]
        if low_and_slow["enabled"]:
            candidates += detect_low_and_slow_bruteforce(
                events,
                low_and_slow["threshold"],
                timedelta(seconds=low_and_slow["window_seconds"]),
                brute["threshold"],
                timedelta(seconds=brute["window_seconds"]),
            )
        candidates += detect_password_spraying(
            events, spray["username_threshold"], timedelta(seconds=spray["window_seconds"])
        )
        candidates += detect_username_enumeration(
            events, enumeration["threshold"], timedelta(seconds=enumeration["window_seconds"])
        )
        candidates += detect_root_attempts(
            events,
            timedelta(seconds=settings["root_attempts"]["window_seconds"]),
            settings["root_attempts"]["minimum_attempts"],
        )
        candidates += detect_success_after_failures(
            events, success["failure_threshold"], timedelta(seconds=success["lookback_seconds"])
        )
        candidates += detect_distributed_bruteforce(
            events, distributed["ip_threshold"], timedelta(seconds=distributed["window_seconds"])
        )
        candidates += detect_off_hours_login(
            events,
            off_hours["business_start"],
            off_hours["business_end"],
            timedelta(seconds=success["lookback_seconds"]),
        )
        candidates += detect_new_source_ip_login(
            events, allowlist, settings["new_source_ip"]["trusted_local_sources"]
        )
    elif log_type == "web":
        from web_detections import (
            detect_web_login_bruteforce,
            detect_web_scanning,
            detect_web_success_after_failures,
            detect_web_suspicious_user_agent,
        )

        web = settings["web"]
        candidates += detect_web_login_bruteforce(
            events,
            web["login_threshold"],
            timedelta(seconds=web["login_window_seconds"]),
            web["login_paths"],
        )
        candidates += detect_web_scanning(
            events,
            web["scanning_404_threshold"],
            timedelta(seconds=web["scanning_window_seconds"]),
        )
        candidates += detect_web_suspicious_user_agent(
            events,
            web["suspicious_user_agents"],
            timedelta(seconds=web["user_agent_window_seconds"]),
        )
        candidates += detect_web_success_after_failures(
            events,
            web["success_after_failures_threshold"],
            timedelta(seconds=web["login_window_seconds"]),
            web["login_paths"],
        )
    else:
        raise ValueError("log_type must be 'ssh' or 'web'")
    suppressible = {
        "ssh_brute_force",
        "ssh_low_and_slow_bruteforce",
        "ssh_password_spraying",
        "ssh_username_enumeration",
        "ssh_root_login_attempt",
        "ssh_distributed_bruteforce",
        "ssh_success_after_failures",
        "ssh_off_hours_login",
        "web_login_bruteforce",
        "web_scanning",
        "web_suspicious_user_agent",
        "web_success_after_failures",
    }
    kept = []
    suppressed = 0
    for alert in candidates:
        if alert["rule"] not in suppressible or not allowlist:
            kept.append(alert)
            continue
        if alert.get("source_ip") and is_allowlisted(alert["source_ip"], allowlist):
            suppressed += 1
            continue
        if alert["rule"] == "ssh_distributed_bruteforce":
            ips = [ip for ip in alert["source_ips"] if not is_allowlisted(ip, allowlist)]
            if len(ips) < distributed["ip_threshold"]:
                suppressed += 1
                continue
            alert["source_ips"] = ips
            alert["distinct_source_ips"] = len(ips)
            alert["attempt_count"] = len(ips)
            alert["attempts"] = len(ips)
        kept.append(alert)
    merge_gap = settings["alert_merging"]["merge_gap_seconds"]
    kept = merge_adjacent_alerts(kept, merge_gap)
    severity_config = settings["severity_thresholds"]
    for alert in kept:
        attempts = alert.get("attempt_count", 0)
        if alert["rule"] in {
            "ssh_brute_force",
            "ssh_root_login_attempt",
            "web_login_bruteforce",
            "web_scanning",
        }:
            alert["severity"] = (
                "High"
                if attempts >= severity_config["high_attempts"]
                else ("Medium" if alert["rule"] != "ssh_root_login_attempt" else "Low")
            )
            if attempts >= severity_config["sustained_attempts"]:
                alert["description"] = (
                    f"Sustained activity: {_count_word(attempts)} across adjacent windows."
                )
            elif alert["rule"] == "ssh_root_login_attempt":
                alert["description"] = f"{_count_word(attempts, 'failed attempt')} targeted root."
        alert["base_severity"] = alert["severity"]
        for private_key in ("_merge_event_ids", "_merge_attempt_ids", "_merge_attempt_counts"):
            alert.pop(private_key, None)
    return kept, suppressed


def run_all_detections(
    events: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Run all rules and return their aggregated alerts."""
    alerts, _ = _detect_all(events, config, allowlist)
    for alert in alerts:
        alert.pop("_incident_event_counts", None)
    return alerts


def correlate_incidents(
    alerts: list[dict[str, Any]],
    risk_scores: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Group overlapping alerts and assign composite severity from source risk."""
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        ip = alert.get("source_ip")
        if ip:
            by_ip[ip].append(alert)
    incidents = []
    for ip, group in sorted(by_ip.items()):
        group.sort(key=lambda a: a["first_seen"] or datetime.min)
        buckets: list[list[dict[str, Any]]] = []
        for alert in group:
            placed = False
            for bucket in buckets:
                starts = [item["first_seen"] for item in bucket if item["first_seen"]]
                ends = [item["last_seen"] for item in bucket if item["last_seen"]]
                if (
                    starts
                    and ends
                    and alert["first_seen"] <= max(ends)
                    and alert["last_seen"] >= min(starts)
                ):
                    bucket.append(alert)
                    placed = True
                    break
            if not placed:
                buckets.append([alert])
        for bucket in buckets:
            rules = sorted({item["rule"] for item in bucket})
            if len(rules) < 2:
                continue
            base_severity = max(
                (item.get("base_severity", item["severity"]) for item in bucket),
                key=SEVERITY_ORDER.get,
            )
            source_risk = (risk_scores or {}).get(ip)
            score = source_risk.get("score") if source_risk else None
            band = risk_band(score) if score is not None else None
            severity = band or base_severity
            if band is None and "ssh_success_after_failures" in rules:
                severity = {
                    "Low": "Medium",
                    "Medium": "High",
                    "High": "High",
                    "Critical": "Critical",
                }[severity]
            first = min(item["first_seen"] for item in bucket if item["first_seen"])
            last = max(item["last_seen"] for item in bucket if item["last_seen"])
            event_counts: dict[Any, int] = {}
            for item in bucket:
                for identity, count in item.get("_incident_event_counts", {}).items():
                    event_counts[identity] = max(event_counts.get(identity, 0), count)
            usernames = sorted(
                set().union(*(set(item.get("usernames_targeted", [])) for item in bucket))
            )
            authentication_methods = sorted(
                set().union(*(set(item.get("authentication_methods", [])) for item in bucket))
            )
            session_activity: dict[tuple[Any, ...], dict[str, Any]] = {}
            supporting_evidence: dict[Any, dict[str, Any]] = {}
            evidence_event_ids: set[Any] = set()
            for item in bucket:
                evidence_event_ids.update(item.get("_incident_event_counts", {}).keys())
                for evidence in item.get("supporting_evidence", []):
                    evidence_id = evidence.get("event_id")
                    if evidence_id is not None:
                        supporting_evidence[evidence_id] = evidence
                        evidence_event_ids.add(evidence_id)
                for session in item.get("session_activity", []):
                    identity = (
                        session.get("event_type"),
                        session.get("timestamp"),
                        session.get("hostname"),
                        session.get("process_id"),
                        session.get("username"),
                    )
                    session_activity[identity] = session
            incidents.append(
                {
                    "incident_id": f"INC-{len(incidents) + 1:03d}",
                    "source_ip": ip,
                    "first_seen": first,
                    "last_seen": last,
                    "contributing_rules": rules,
                    "combined_severity": severity,
                    "summary": f"{len(rules)} detection rules overlapped for {ip}: {', '.join(rules)}.",
                    **({"attempt_count": sum(event_counts.values())} if event_counts else {}),
                    "usernames_targeted": usernames,
                    "authentication_methods": authentication_methods,
                    "evidence_event_ids": sorted(
                        (event_id for event_id in evidence_event_ids if isinstance(event_id, str)),
                        key=str,
                    ),
                    **(
                        {
                            "supporting_evidence": sorted(
                                supporting_evidence.values(),
                                key=lambda item: item.get("timestamp", datetime.min),
                            )
                        }
                        if supporting_evidence
                        else {}
                    ),
                    **(
                        {
                            "session_activity": sorted(
                                session_activity.values(),
                                key=lambda session: session["timestamp"],
                            )
                        }
                        if session_activity
                        else {}
                    ),
                    **({"risk_score": score, "risk_band": band} if band is not None else {}),
                }
            )
    return incidents


def calculate_risk_scores(
    events: list[dict[str, Any]], alerts: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Score sources using capped rule breadth, log-scaled volume, and confirmed outcomes.

    Formula: min(10 × distinct rules, 40) + min(20 × log1p(failures) /
    log1p(1000), 20) + 15 for root targeting + 30 for a confirmed success
    after failures; clamp to 0–100. Confirmed SSH or web success-after-failures
    guarantees Critical (75); all other activity is capped at 74. Bands are
    0–24 Low, 25–49 Medium, 50–74 High, and 75–100 Critical. Shared NAT egress
    can combine unrelated users and overstate one source's risk.
    """
    grouped = group_events_by_ip(events)
    alert_rules: dict[str, set[str]] = defaultdict(set)
    for alert in alerts:
        ip = alert.get("source_ip")
        if ip:
            alert_rules[ip].add(alert["rule"])
        for source_ip in alert.get("source_ips", []):
            alert_rules[source_ip].add(alert["rule"])
    scores = {}
    for ip, ip_events in grouped.items():
        failures = sum(_event_occurrences(e) for e in ip_events if _is_failure(e))
        root = any(_is_failure(e) and e.get("username") == "root" for e in ip_events)
        success_after = bool(
            {"ssh_success_after_failures", "web_success_after_failures"} & alert_rules[ip]
        )
        score = min(len(alert_rules[ip]) * RISK_PER_RULE, RISK_RULE_CAP)
        volume_score = int(
            RISK_VOLUME_WEIGHT * math.log1p(failures) / math.log1p(RISK_VOLUME_REFERENCE)
        )
        score += min(volume_score, RISK_VOLUME_CAP)
        score += RISK_ROOT_TARGETING if root else 0
        score += RISK_SUCCESS_AFTER_FAILURES if success_after else 0
        score = min(100, max(0, score))
        if success_after:
            score = max(score, RISK_CONFIRMED_SUCCESS_FLOOR)
        else:
            score = min(score, RISK_UNCONFIRMED_CAP)
        band = risk_band(score)
        scores[ip] = {"score": score, "band": band}
    attempt_counts = {ip: _event_count(ip_events) for ip, ip_events in grouped.items()}
    last_seen = {
        ip: max((get_event_time(event) for event in ip_events), default=datetime.min)
        for ip, ip_events in grouped.items()
    }
    return dict(
        sorted(
            scores.items(),
            key=lambda item: (
                -item[1]["score"],
                -attempt_counts[item[0]],
                -last_seen[item[0]].timestamp(),
                item[0],
            ),
        )
    )


def calculate_risk_explanations(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    risk_scores: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Explain existing source-risk scores without changing their calculation."""
    canonical_scores = risk_scores or calculate_risk_scores(events, alerts)
    grouped = group_events_by_ip(events)
    alert_rules: dict[str, set[str]] = defaultdict(set)
    for alert in alerts:
        source = alert.get("source_ip")
        if source:
            alert_rules[source].add(alert["rule"])
        for source in alert.get("source_ips", []):
            alert_rules[source].add(alert["rule"])

    explanations = {}
    for source_ip, source_events in grouped.items():
        failures = sum(_event_occurrences(event) for event in source_events if _is_failure(event))
        root_failure_count = sum(
            _event_occurrences(event)
            for event in source_events
            if _is_failure(event) and event.get("username") == "root"
        )
        rules = alert_rules[source_ip]
        confirmed_success_signal = bool(
            {"ssh_success_after_failures", "web_success_after_failures"} & rules
        )
        rule_points = min(len(rules) * RISK_PER_RULE, RISK_RULE_CAP)
        volume_points = min(
            int(RISK_VOLUME_WEIGHT * math.log1p(failures) / math.log1p(RISK_VOLUME_REFERENCE)),
            RISK_VOLUME_CAP,
        )
        root_points = RISK_ROOT_TARGETING if root_failure_count else 0
        success_points = RISK_SUCCESS_AFTER_FAILURES if confirmed_success_signal else 0
        subtotal = rule_points + volume_points + root_points + success_points
        canonical = canonical_scores[source_ip]
        adjustment = canonical["score"] - subtotal
        explanations[source_ip] = {
            "score": canonical["score"],
            "band": canonical["band"],
            "factors": {
                "rule_breadth": {
                    "evidence": len(rules),
                    "contribution": rule_points,
                    "policy": f"{RISK_PER_RULE} points per distinct rule, capped at {RISK_RULE_CAP}.",
                },
                "failure_volume": {
                    "evidence": failures,
                    "contribution": volume_points,
                    "policy": (
                        f"{RISK_VOLUME_WEIGHT} × log1p(failures) / log1p({RISK_VOLUME_REFERENCE}), "
                        f"capped at {RISK_VOLUME_CAP}; weighted terminal failures only."
                    ),
                },
                "root_targeting": {
                    "evidence": root_failure_count,
                    "contribution": root_points,
                    "policy": f"Add {RISK_ROOT_TARGETING} points when at least one failed root attempt is present.",
                },
                "success_after_failures": {
                    "evidence": confirmed_success_signal,
                    "contribution": success_points,
                    "policy": (
                        f"Add {RISK_SUCCESS_AFTER_FAILURES} points when the success-after-failures "
                        "detection is present."
                    ),
                },
            },
            "policy_adjustment": {
                "contribution": adjustment,
                "floor_applied": confirmed_success_signal
                and subtotal < RISK_CONFIRMED_SUCCESS_FLOOR,
                "unconfirmed_cap_applied": not confirmed_success_signal
                and subtotal > RISK_UNCONFIRMED_CAP,
                "policy": (
                    f"Apply the existing 0–100 clamp, Critical floor {RISK_CONFIRMED_SUCCESS_FLOOR} "
                    f"for success-after-failures, and unconfirmed cap {RISK_UNCONFIRMED_CAP}."
                ),
            },
            "confidence": {
                "status": "not_calibrated",
                "rationale": (
                    "No calibrated confidence model or representative labeled real-log corpus is available; "
                    "this score is a triage aid, not a probability of compromise."
                ),
            },
            "uncertainty": (
                "Events sharing a NAT or proxy source may belong to different users; "
                "log volume and rule breadth do not establish a common actor."
            ),
        }
    return explanations


def analyze_events(
    events: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
    allowlist: list[Any] | None = None,
    log_type: str = "ssh",
) -> dict[str, Any]:
    """Run detections and derive correlated incidents and explainable risk scores."""
    alerts, suppressed = _detect_all(events, config, allowlist, log_type=log_type)
    risk_scores = calculate_risk_scores(events, alerts)
    for alert in alerts:
        alert["base_severity"] = alert.get("base_severity", alert["severity"])
        source_risk = risk_scores.get(alert.get("source_ip"))
        if source_risk:
            alert["source_risk_score"] = source_risk["score"]
            alert["source_risk_band"] = source_risk["band"]
            # Keep the original report keys as aliases for existing consumers.
            alert["risk_score"] = source_risk["score"]
            alert["risk_band"] = source_risk["band"]
    incidents = correlate_incidents(alerts, risk_scores)
    risk_explanations = calculate_risk_explanations(events, alerts, risk_scores)
    for alert in alerts:
        alert.pop("_incident_event_counts", None)
    return {
        "alerts": alerts,
        "incidents": incidents,
        "risk_scores": risk_scores,
        "risk_explanations": risk_explanations,
        "alerts_suppressed": suppressed,
    }


if __name__ == "__main__":
    from ssh_parser import parse_log_file

    parsed, _stats = parse_log_file("sample_logs/auth.log")
    result = analyze_events(parsed)
    print(f"Events analyzed : {len(parsed)}")
    print(f"Alerts generated: {len(result['alerts'])}")
