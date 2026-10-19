"""Web-access-log detections that share the SSH alert schema."""

from __future__ import annotations

from collections import deque
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from config import is_allowlisted
from detections import _base_alert, _clusters, _count_word, get_event_time, group_events_by_ip

DEFAULT_LOGIN_PATHS = ("/login", "/wp-login.php", "/admin")
DEFAULT_USER_AGENTS = ("sqlmap", "nikto", "nmap", "masscan", "acunetix")


def detect_web_login_bruteforce(
    events: list[dict[str, Any]],
    threshold: int = 5,
    window: timedelta = timedelta(seconds=60),
    login_paths: tuple[str, ...] | list[str] = DEFAULT_LOGIN_PATHS,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect repeated 401/403 responses on configured login endpoints."""
    if threshold < 1 or window < timedelta(0):
        raise ValueError("threshold must be positive and window cannot be negative")
    paths = set(login_paths)
    relevant = [
        event
        for event in events
        if event.get("status") in (401, 403)
        and urlsplit(event.get("path", "")).path in paths
        and not is_allowlisted(event.get("source_ip"), allowlist)
    ]
    alerts = []
    for source_ip, group in group_events_by_ip(relevant).items():
        for cluster in _clusters(group, window):
            if len(cluster) < threshold:
                continue
            request_paths = sorted({event.get("path", "") for event in cluster})
            alerts.append(
                _base_alert(
                    "web_login_bruteforce",
                    "Medium",
                    source_ip,
                    cluster,
                    f"{_count_word(len(cluster), 'unauthorized response')} hit configured login paths within {int(window.total_seconds())} seconds.",
                    attempt_count=len(cluster),
                    paths=request_paths,
                    path=request_paths,
                    statuses=sorted({event["status"] for event in cluster}),
                    window_seconds=int(window.total_seconds()),
                )
            )
    return alerts


def detect_web_scanning(
    events: list[dict[str, Any]],
    threshold: int = 10,
    window: timedelta = timedelta(seconds=60),
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect a high count of 404 responses from one source IP."""
    if threshold < 1 or window < timedelta(0):
        raise ValueError("threshold must be positive and window cannot be negative")
    relevant = [
        event
        for event in events
        if event.get("status") == 404 and not is_allowlisted(event.get("source_ip"), allowlist)
    ]
    alerts = []
    for source_ip, group in group_events_by_ip(relevant).items():
        for cluster in _clusters(group, window):
            if len(cluster) < threshold:
                continue
            paths = sorted({event.get("path", "") for event in cluster})
            alerts.append(
                _base_alert(
                    "web_scanning",
                    "Medium",
                    source_ip,
                    cluster,
                    f"{_count_word(len(cluster), 'not-found response')} from one source indicate possible path scanning.",
                    attempt_count=len(cluster),
                    paths=paths,
                    path=paths,
                    window_seconds=int(window.total_seconds()),
                )
            )
    return alerts


def detect_web_suspicious_user_agent(
    events: list[dict[str, Any]],
    patterns: tuple[str, ...] | list[str] = DEFAULT_USER_AGENTS,
    window: timedelta = timedelta(seconds=60),
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect configured scanner/tool names in request User-Agent strings."""
    if window < timedelta(0):
        raise ValueError("window cannot be negative")
    normalized = [pattern.casefold() for pattern in patterns]
    relevant = [
        event
        for event in events
        if event.get("user_agent")
        and any(pattern in event["user_agent"].casefold() for pattern in normalized)
        and not is_allowlisted(event.get("source_ip"), allowlist)
    ]
    alerts = []
    for source_ip, group in group_events_by_ip(relevant).items():
        for cluster in _clusters(group, window):
            agents = sorted({event["user_agent"] for event in cluster})
            alerts.append(
                _base_alert(
                    "web_suspicious_user_agent",
                    "Low",
                    source_ip,
                    cluster,
                    f"Configured suspicious User-Agent pattern matched in {_count_word(len(cluster), 'request')}.",
                    attempt_count=len(cluster),
                    user_agent=agents,
                    user_agents=agents,
                    paths=sorted({event.get("path", "") for event in cluster}),
                    path=sorted({event.get("path", "") for event in cluster}),
                    window_seconds=int(window.total_seconds()),
                )
            )
    return alerts


def detect_web_success_after_failures(
    events: list[dict[str, Any]],
    threshold: int = 5,
    lookback: timedelta = timedelta(seconds=60),
    login_paths: tuple[str, ...] | list[str] = DEFAULT_LOGIN_PATHS,
    allowlist: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Detect a successful login-path response after repeated unauthorized responses."""
    if threshold < 1 or lookback < timedelta(0):
        raise ValueError("threshold must be positive and lookback cannot be negative")
    paths = set(login_paths)
    alerts = []
    for source_ip, group in group_events_by_ip(events).items():
        if is_allowlisted(source_ip, allowlist):
            continue
        failures: deque[dict[str, Any]] = deque()
        for event in sorted(group, key=get_event_time):
            stamp = get_event_time(event)
            while failures and stamp - get_event_time(failures[0]) > lookback:
                failures.popleft()
            if event.get("status") in (401, 403) and urlsplit(event.get("path", "")).path in paths:
                failures.append(event)
            elif (
                event.get("status", 0) in range(200, 300)
                and urlsplit(event.get("path", "")).path in paths
                and len(failures) >= threshold
            ):
                records = [*failures, event]
                alerts.append(
                    _base_alert(
                        "web_success_after_failures",
                        "High",
                        source_ip,
                        records,
                        "A successful login-path response followed repeated unauthorized responses from the same source IP.",
                        attempt_count=len(failures),
                        failed_attempts=len(failures),
                        window_seconds=int(lookback.total_seconds()),
                    )
                )
    return alerts
