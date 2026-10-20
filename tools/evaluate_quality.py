"""Run a closed-set, deterministic synthetic evaluation of all current rules."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from detections import analyze_events
from ssh_parser import parse_log_file

ROOT = Path(__file__).resolve().parents[1]
REPEATED_FIXTURE = ROOT / "sample_logs" / "repeated_syslog_semantics.log"
BASE_TIME = datetime(2026, 10, 19, 9, 0)
RULES = (
    "ssh_brute_force",
    "ssh_low_and_slow_bruteforce",
    "ssh_password_spraying",
    "ssh_username_enumeration",
    "ssh_root_login_attempt",
    "ssh_success_after_failures",
    "ssh_distributed_bruteforce",
    "ssh_off_hours_login",
    "ssh_new_source_ip_login",
    "web_login_bruteforce",
    "web_scanning",
    "web_suspicious_user_agent",
    "web_success_after_failures",
)


def _ssh_event(
    source_ip: str,
    second: int,
    *,
    username: str = "analyst",
    event_type: str = "authentication_failure",
    invalid_user: bool = False,
    occurrence_count: int = 1,
) -> dict[str, Any]:
    """Build one deterministic synthetic normalized SSH record."""
    return {
        "_event_id": f"synthetic:{source_ip}:{second}:{username}:{event_type}",
        "timestamp": BASE_TIME + timedelta(seconds=second),
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "invalid_user": invalid_user,
        "is_root": username == "root",
        "authentication_method": "password",
        "occurrence_count": occurrence_count,
    }


def _web_event(
    source_ip: str,
    second: int,
    *,
    path: str = "/",
    status: int = 200,
    user_agent: str = "ExampleBrowser/1.0",
) -> dict[str, Any]:
    """Build one deterministic synthetic normalized HTTP request."""
    return {
        "_event_id": f"synthetic:{source_ip}:{second}:{path}:{status}",
        "timestamp": BASE_TIME + timedelta(seconds=second),
        "source_ip": source_ip,
        "event_type": "web_request",
        "method": "POST" if path in {"/login", "/admin"} else "GET",
        "path": path,
        "status": status,
        "bytes": 100,
        "referrer": "-",
        "user_agent": user_agent,
    }


def _scenarios() -> list[dict[str, Any]]:
    """Return input scenarios paired with outcomes declared before execution."""
    ssh = lambda ip, seconds, **kwargs: [  # noqa: E731
        _ssh_event(ip, second, **kwargs) for second in seconds
    ]
    web = lambda ip, seconds, **kwargs: [  # noqa: E731
        _web_event(ip, second, **kwargs) for second in seconds
    ]

    cases: list[dict[str, Any]] = [
        {
            "name": "benign_ssh_authentication",
            "log_type": "ssh",
            "events": ssh(
                "192.0.2.10",
                [0, 180, 360],
                event_type="authentication_success",
            ),
            "expected": {},
        },
        {
            "name": "ssh_brute_force_single_account",
            "log_type": "ssh",
            "events": ssh("198.51.100.11", [0, 5, 10, 15, 20], username="analyst"),
            "expected": {"ssh_brute_force": 1},
        },
        {
            "name": "ssh_low_and_slow_failures_over_20_hours",
            "log_type": "ssh",
            "events": ssh("203.0.113.60", [hour * 3600 for hour in range(20)]),
            "expected": {"ssh_low_and_slow_bruteforce": 1},
            "config": {"low_and_slow": {"enabled": True}},
        },
        {
            "name": "ssh_low_and_slow_below_threshold",
            "log_type": "ssh",
            "events": ssh("203.0.113.61", [hour * 3600 for hour in range(19)]),
            "expected": {},
            "config": {"low_and_slow": {"enabled": True}},
        },
        {
            "name": "ssh_low_and_slow_excludes_short_bruteforce_burst",
            "log_type": "ssh",
            "events": ssh("203.0.113.62", [0, 1, 2, 3, 4])
            + ssh("203.0.113.62", [hour * 3600 for hour in range(1, 16)]),
            "expected": {"ssh_brute_force": 1},
            "config": {"low_and_slow": {"enabled": True}},
        },
        {
            "name": "ssh_brute_force_below_threshold",
            "log_type": "ssh",
            "events": ssh("198.51.100.28", [0, 5, 10, 15]),
            "expected": {},
        },
        {
            "name": "ssh_brute_force_outside_window",
            "log_type": "ssh",
            "events": ssh("198.51.100.29", [0, 70, 140, 210, 280]),
            "expected": {},
        },
        {
            "name": "ssh_password_spray_overlaps_brute_force",
            "log_type": "ssh",
            "events": ssh(
                "198.51.100.12",
                [0, 5, 10, 15, 20],
                username=None,
            ),
            "expected": {"ssh_brute_force": 1, "ssh_password_spraying": 1},
            "username_sequence": ["alice", "bob", "carol", "dave", "erin"],
        },
        {
            "name": "ssh_password_spraying_below_threshold",
            "log_type": "ssh",
            "events": [
                _ssh_event("198.51.100.43", second, username=name)
                for second, name in zip([0, 5, 10, 15], ["alice", "bob", "carol", "dave"])
            ],
            "expected": {},
        },
        {
            "name": "ssh_username_enumeration",
            "log_type": "ssh",
            "events": [
                _ssh_event("203.0.113.13", second, username=name, invalid_user=True)
                for second, name in zip([0, 5, 10, 15], ["ghost1", "ghost2", "ghost3", "ghost4"])
            ],
            "expected": {"ssh_username_enumeration": 1},
        },
        {
            "name": "ssh_username_enumeration_below_threshold",
            "log_type": "ssh",
            "events": [
                _ssh_event("203.0.113.36", second, username=name, invalid_user=True)
                for second, name in zip([0, 5, 10], ["ghost1", "ghost2", "ghost3"])
            ],
            "expected": {},
        },
        {
            "name": "ssh_repeated_syslog_message",
            "log_type": "ssh",
            "events": None,
            "expected": {"ssh_brute_force": 1, "ssh_root_login_attempt": 1},
            "fixture": str(REPEATED_FIXTURE),
        },
        {
            "name": "ssh_success_after_failures",
            "log_type": "ssh",
            "events": ssh("198.51.100.15", [0, 5, 10, 15, 20], username="admin")
            + ssh(
                "198.51.100.15",
                [25],
                username="admin",
                event_type="authentication_success",
            ),
            "expected": {"ssh_brute_force": 1, "ssh_success_after_failures": 1},
        },
        {
            "name": "ssh_success_after_failures_below_threshold",
            "log_type": "ssh",
            "events": ssh("198.51.100.44", [0, 5, 10, 15], username="admin")
            + ssh(
                "198.51.100.44",
                [20],
                username="admin",
                event_type="authentication_success",
            ),
            "expected": {},
        },
        {
            "name": "ssh_adjacent_windows_remain_separate",
            "log_type": "ssh",
            "events": ssh("203.0.113.16", [0, 10, 20, 30, 40, 101, 111, 121, 131, 141]),
            "expected": {"ssh_brute_force": 2},
        },
        {
            "name": "legitimate_admin_resembles_low_volume_failures",
            "log_type": "ssh",
            "events": ssh("192.0.2.17", [0, 5, 10, 15], username="administrator")
            + ssh(
                "192.0.2.17",
                [20],
                username="administrator",
                event_type="authentication_success",
            ),
            "expected": {},
        },
        {
            "name": "ssh_root_authentication_failures",
            "log_type": "ssh",
            "events": ssh("203.0.113.18", [0, 10, 20], username="root"),
            "expected": {"ssh_root_login_attempt": 1},
        },
        {
            "name": "ssh_root_attempts_below_threshold",
            "log_type": "ssh",
            "events": ssh("203.0.113.37", [0, 10], username="root"),
            "expected": {},
        },
        {
            "name": "legitimate_root_admin_activity_is_a_false_positive",
            "log_type": "ssh",
            "events": ssh("203.0.113.38", [0, 10, 20], username="root"),
            "expected": {"ssh_root_login_attempt": 1},
            "truth": {},
        },
        {
            "name": "ssh_distributed_bruteforce",
            "log_type": "ssh",
            "events": [
                _ssh_event(f"198.51.100.{20 + index}", index * 20, username="target")
                for index in range(5)
            ],
            "expected": {"ssh_distributed_bruteforce": 1},
        },
        {
            "name": "ssh_distributed_bruteforce_below_ip_threshold",
            "log_type": "ssh",
            "events": [
                _ssh_event(f"198.51.100.{40 + index}", index * 20, username="target")
                for index in range(4)
            ],
            "expected": {},
        },
        {
            "name": "ssh_off_hours_login",
            "log_type": "ssh",
            "events": [
                {
                    **_ssh_event(
                        "203.0.113.25",
                        0,
                        username="oncall",
                        event_type="authentication_success",
                    ),
                    "timestamp": datetime(2026, 10, 19, 2, 0),
                }
            ],
            "expected": {"ssh_off_hours_login": 1},
        },
        {
            "name": "ssh_new_source_ip_login",
            "log_type": "ssh",
            "events": ssh(
                "203.0.113.26", [0], username="analyst", event_type="authentication_success"
            ),
            "expected": {"ssh_new_source_ip_login": 1},
        },
        {
            "name": "ssh_known_source_ip_login",
            "log_type": "ssh",
            "events": ssh(
                "203.0.113.25", [0], username="oncall", event_type="authentication_success"
            ),
            "expected": {},
        },
        {
            "name": "benign_web_requests",
            "log_type": "web",
            "events": web("192.0.2.30", [0, 60, 120], status=200),
            "expected": {},
        },
        {
            "name": "web_login_failures",
            "log_type": "web",
            "events": web("198.51.100.31", [0, 5, 10, 15, 20], path="/login", status=401),
            "expected": {"web_login_bruteforce": 1},
        },
        {
            "name": "web_login_failures_below_threshold",
            "log_type": "web",
            "events": web("198.51.100.40", [0, 5, 10, 15], path="/login", status=401),
            "expected": {},
        },
        {
            "name": "web_scanning",
            "log_type": "web",
            "events": [
                _web_event("203.0.113.32", second, path=f"/missing-{index}", status=404)
                for index, second in enumerate(range(10))
            ],
            "expected": {"web_scanning": 1},
        },
        {
            "name": "web_scanning_below_threshold",
            "log_type": "web",
            "events": [
                _web_event("203.0.113.41", second, path=f"/missing-{index}", status=404)
                for index, second in enumerate(range(9))
            ],
            "expected": {},
        },
        {
            "name": "web_suspicious_user_agent",
            "log_type": "web",
            "events": [_web_event("198.51.100.33", 0, user_agent="Nmap Scripting Engine")],
            "expected": {"web_suspicious_user_agent": 1},
        },
        {
            "name": "web_success_after_login_failures",
            "log_type": "web",
            "events": web("203.0.113.34", [0, 5, 10, 15, 20], path="/admin", status=403)
            + web("203.0.113.34", [25], path="/admin", status=200),
            "expected": {"web_login_bruteforce": 1, "web_success_after_failures": 1},
        },
        {
            "name": "web_success_after_failures_below_threshold",
            "log_type": "web",
            "events": web("203.0.113.42", [0, 5, 10, 15], path="/login", status=401)
            + web("203.0.113.42", [20], path="/login", status=200),
            "expected": {},
        },
    ]

    for case in cases:
        if case["name"] == "ssh_password_spray_overlaps_brute_force":
            case["events"] = [
                _ssh_event("198.51.100.12", second, username=username)
                for second, username in zip([0, 5, 10, 15, 20], case.pop("username_sequence"))
            ]
        if case.get("fixture"):
            case["events"], _stats = parse_log_file(case["fixture"], year=2026)
    return cases


def _rounded_metric(value: float | None) -> float | None:
    """Make metric output stable and readable without hiding undefined values."""
    return round(value, 4) if value is not None else None


def evaluate_scenarios() -> dict[str, Any]:
    """Compare analyzer output with explicit per-scenario expected alert counts."""
    cases = _scenarios()
    # Known fixture sources are trusted only for the opt-in new-source rule.
    # All addresses remain documentation ranges; other detections see allowlist=[].
    trusted = [
        f"{event['source_ip']}/32"
        for case in cases
        if case["log_type"] == "ssh" and case["name"] != "ssh_new_source_ip_login"
        for event in case["events"]
        if event.get("source_ip")
    ]
    trusted = sorted(set(trusted))
    config = {"new_source_ip": {"trusted_local_sources": trusted}}
    results = []
    rule_totals = {rule: Counter() for rule in RULES}
    for case in cases:
        scenario_config = {"new_source_ip": config["new_source_ip"]}
        scenario_config.update(case.get("config", {}))
        if case["log_type"] == "ssh":
            result = analyze_events(case["events"], config=scenario_config, allowlist=[])
        else:
            result = analyze_events(case["events"], log_type="web")
        actual_counts = dict(sorted(Counter(alert["rule"] for alert in result["alerts"]).items()))
        expected = case["expected"]
        truth = case.get("truth", expected)
        for rule in RULES:
            expected_present = truth.get(rule, 0) > 0
            actual_present = actual_counts.get(rule, 0) > 0
            if expected_present and actual_present:
                rule_totals[rule]["true_positive"] += 1
            elif expected_present:
                rule_totals[rule]["false_negative"] += 1
            elif actual_present:
                rule_totals[rule]["false_positive"] += 1

        alert_rows = [
            {
                "rule": alert["rule"],
                "source_ip": alert.get("source_ip"),
                "first_seen": alert.get("first_seen"),
                "last_seen": alert.get("last_seen"),
                "attempt_count": alert.get("attempt_count"),
                "base_severity": alert.get("base_severity"),
                "description": alert["description"],
            }
            for alert in result["alerts"]
        ]
        incident_rows = [
            {
                key: incident[key]
                for key in (
                    "contributing_rules",
                    "attempt_count",
                    "risk_score",
                    "risk_band",
                    "combined_severity",
                )
                if key in incident
            }
            for incident in result["incidents"]
        ]
        results.append(
            {
                "name": case["name"],
                "log_type": case["log_type"],
                "expected_alert_counts": expected,
                "ground_truth_rules": sorted(truth),
                "predicted_alert_counts": actual_counts,
                "attempt_counts": [alert["attempt_count"] for alert in alert_rows],
                "alerts": alert_rows,
                "incidents": incident_rows,
                "risk_scores": result["risk_scores"],
                "matches_expected": actual_counts == expected,
            }
        )

    metrics = {}
    for rule, counts in rule_totals.items():
        tp = counts["true_positive"]
        fp = counts["false_positive"]
        fn = counts["false_negative"]
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = None
        if precision is not None and recall is not None:
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        metrics[rule] = {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "scenario_support": sum(
                case.get("truth", case["expected"]).get(rule, 0) > 0 for case in cases
            ),
            "precision": _rounded_metric(precision),
            "recall": _rounded_metric(recall),
            "f1": _rounded_metric(f1),
        }
    return {
        "evaluation_scope": "closed-set deterministic synthetic scenarios; not real-world accuracy",
        "scenario_count": len(results),
        "matches_expected": all(case["matches_expected"] for case in results),
        "metrics": metrics,
        "scenarios": results,
    }


def main() -> int:
    """Print JSON metrics and return nonzero if any case differs from its labels."""
    report = evaluate_scenarios()
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0 if report["matches_expected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
