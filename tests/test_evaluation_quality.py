"""Ground-truth checks for deterministic synthetic detection scenarios."""

from tools.evaluate_quality import evaluate_scenarios


def test_synthetic_quality_scenarios_match_declared_rule_labels():
    """Every fixture scenario matches its reviewed expected rule/count labels."""
    report = evaluate_scenarios()

    assert report["matches_expected"] is True
    assert report["scenario_count"] >= 12
    assert set(report["metrics"]) == {
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
    }
    assert all(metric["false_negative"] == 0 for metric in report["metrics"].values())
    assert report["metrics"]["ssh_root_login_attempt"] == {
        "true_positive": 2,
        "false_positive": 1,
        "false_negative": 0,
        "scenario_support": 2,
        "precision": 0.6667,
        "recall": 1.0,
        "f1": 0.8,
    }
    assert all(
        metric["false_positive"] == 0
        for rule, metric in report["metrics"].items()
        if rule != "ssh_root_login_attempt"
    )
    assert report["metrics"]["ssh_off_hours_login"]["true_positive"] == 1
    assert report["metrics"]["web_success_after_failures"]["true_positive"] == 1
    assert report["metrics"]["ssh_low_and_slow_bruteforce"] == {
        "true_positive": 1,
        "false_positive": 0,
        "false_negative": 0,
        "scenario_support": 1,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }


def test_quality_scenarios_surface_overlap_and_adjacent_window_evidence():
    """Rule overlap stays visible and distinct adjacent windows retain counts."""
    report = evaluate_scenarios()
    scenarios = {scenario["name"]: scenario for scenario in report["scenarios"]}

    overlap = scenarios["ssh_password_spray_overlaps_brute_force"]
    assert overlap["predicted_alert_counts"] == {
        "ssh_brute_force": 1,
        "ssh_password_spraying": 1,
    }
    assert overlap["incidents"] == [
        {
            "contributing_rules": ["ssh_brute_force", "ssh_password_spraying"],
            "attempt_count": 5,
            "risk_score": 25,
            "risk_band": "Medium",
            "combined_severity": "Medium",
        }
    ]

    adjacent = scenarios["ssh_adjacent_windows_remain_separate"]
    assert adjacent["predicted_alert_counts"] == {"ssh_brute_force": 2}
    assert adjacent["attempt_counts"] == [5, 5]
    first, second = adjacent["alerts"]
    assert first["last_seen"] < second["first_seen"]

    burst = scenarios["ssh_low_and_slow_excludes_short_bruteforce_burst"]
    assert burst["predicted_alert_counts"] == {"ssh_brute_force": 1}


def test_success_after_failures_is_a_triage_signal_not_a_proven_compromise():
    """The alert keeps its cautious wording and does not rewrite base severity."""
    report = evaluate_scenarios()
    case = next(
        scenario
        for scenario in report["scenarios"]
        if scenario["name"] == "ssh_success_after_failures"
    )
    alert = next(alert for alert in case["alerts"] if alert["rule"] == "ssh_success_after_failures")

    assert alert["base_severity"] == "High"
    assert "possible account compromise" in alert["description"]
    assert case["risk_scores"]["198.51.100.15"] == {"score": 75, "band": "Critical"}
    assert case["incidents"][0]["combined_severity"] == "Critical"
    assert case["incidents"][0]["attempt_count"] == 6


def test_known_benign_root_administration_is_reported_as_a_synthetic_false_positive():
    """A benign privileged workflow may trigger root-failure triage."""
    report = evaluate_scenarios()
    case = next(
        scenario
        for scenario in report["scenarios"]
        if scenario["name"] == "legitimate_root_admin_activity_is_a_false_positive"
    )

    assert case["ground_truth_rules"] == []
    assert case["expected_alert_counts"] == {"ssh_root_login_attempt": 1}
    assert case["predicted_alert_counts"] == {"ssh_root_login_attempt": 1}
    assert report["metrics"]["ssh_root_login_attempt"]["false_positive"] == 1
