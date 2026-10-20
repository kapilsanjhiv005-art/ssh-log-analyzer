"""Shared occurrence counting for parsed events and presentation layers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any


def event_occurrences(event: Mapping[str, Any]) -> int:
    """Return the positive represented weight, defaulting invalid or absent values to one."""
    value = event.get("occurrence_count", 1)
    return value if isinstance(value, int) and value > 0 else 1


def effective_event_occurrences(events: Iterable[Mapping[str, Any]]) -> int:
    """Sum represented event occurrences without expanding weighted records."""
    return sum(event_occurrences(event) for event in events)


def ssh_authentication_counts(events: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """Count SSH authentication outcomes and root outcomes using event weights."""
    counts: Counter[str] = Counter()
    for event in events:
        outcome = event.get("event_type")
        if outcome == "authentication_failure":
            weight = event_occurrences(event)
            counts["authentication_failures"] += weight
            method = event.get("authentication_method")
            if method == "password":
                counts["password_authentication_failures"] += weight
                if event.get("username") == "root":
                    counts["root_password_authentication_failures"] += weight
            elif method == "none":
                counts["authentication_method_probes"] += weight
            if event.get("username") == "root":
                counts["root_authentication_failures"] += weight
        elif outcome == "authentication_success":
            counts["authentication_successes"] += event_occurrences(event)
            if event.get("username") == "root":
                counts["root_authentication_successes"] += event_occurrences(event)
    return {
        "authentication_failures": counts["authentication_failures"],
        "password_authentication_failures": counts["password_authentication_failures"],
        "authentication_method_probes": counts["authentication_method_probes"],
        "authentication_successes": counts["authentication_successes"],
        "root_authentication_failures": counts["root_authentication_failures"],
        "root_password_authentication_failures": counts["root_password_authentication_failures"],
        "root_authentication_successes": counts["root_authentication_successes"],
    }
