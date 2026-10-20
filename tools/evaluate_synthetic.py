"""Evaluate the analyzer against the small, explicitly labeled synthetic fixture."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from detections import analyze_events
from ssh_parser import parse_log_file

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "sample_logs" / "evaluation_auth.log"
GOLDEN = ROOT / "sample_logs" / "evaluation_golden_alerts.json"


def _alert_key(alert: dict[str, Any]) -> tuple[str, str]:
    """Return the rule/source pair used to match synthetic labels."""
    return alert["rule"], alert["source_ip"]


def evaluate_fixture() -> dict[str, Any]:
    """Return deterministic predictions and per-rule synthetic metrics."""
    expected_rows = json.loads(GOLDEN.read_text(encoding="utf-8"))
    expected = {_alert_key(row): row for row in expected_rows}
    events, _stats = parse_log_file(FIXTURE, year=2026)
    result = analyze_events(events)
    actual = {_alert_key(alert): alert for alert in result["alerts"]}
    rules = sorted({rule for rule, _source in expected | actual})
    metrics = {}
    for rule in rules:
        expected_rule = {key for key in expected if key[0] == rule}
        actual_rule = {key for key in actual if key[0] == rule}
        true_positive = len(expected_rule & actual_rule)
        false_positive = len(actual_rule - expected_rule)
        false_negative = len(expected_rule - actual_rule)
        precision = true_positive / (true_positive + false_positive) if actual_rule else 0.0
        recall = true_positive / (true_positive + false_negative) if expected_rule else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        metrics[rule] = {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
    projection = [
        {
            "rule": alert["rule"],
            "source_ip": alert["source_ip"],
            "attempt_count": alert["attempt_count"],
            "base_severity": alert["base_severity"],
        }
        for alert in result["alerts"]
    ]
    return {
        "expected": expected_rows,
        "predicted": projection,
        "matches_golden": projection == expected_rows,
        "metrics": metrics,
    }


def main() -> int:
    """Print the synthetic evaluation result and return a comparison status."""
    report = evaluate_fixture()
    print("Synthetic fixture metrics only; not a real-world performance estimate.")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["matches_golden"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
