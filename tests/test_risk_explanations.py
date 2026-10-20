"""Risk-score factor explanations must preserve the established composite score."""

from datetime import datetime, timedelta

from detections import calculate_risk_explanations, calculate_risk_scores

BASE = datetime(2026, 10, 19, 9)


def test_risk_explanation_matches_score_and_keeps_confidence_uncalibrated():
    events = [
        {
            "timestamp": BASE + timedelta(seconds=index),
            "source_ip": "192.0.2.44",
            "event_type": "authentication_failure",
            "username": "root" if index == 0 else "analyst",
            "occurrence_count": 1,
        }
        for index in range(5)
    ]
    alerts = [
        {"rule": "ssh_brute_force", "source_ip": "192.0.2.44"},
        {"rule": "ssh_root_login_attempt", "source_ip": "192.0.2.44"},
    ]

    score = calculate_risk_scores(events, alerts)["192.0.2.44"]["score"]
    explanation = calculate_risk_explanations(events, alerts)["192.0.2.44"]

    assert explanation["score"] == score
    assert explanation["band"] == "Medium"
    assert explanation["factors"]["rule_breadth"]["evidence"] == 2
    assert explanation["factors"]["rule_breadth"]["contribution"] == 20
    assert explanation["factors"]["failure_volume"]["evidence"] == 5
    assert explanation["factors"]["root_targeting"]["contribution"] == 15
    assert explanation["factors"]["success_after_failures"]["contribution"] == 0
    assert explanation["confidence"]["status"] == "not_calibrated"
    assert "probability" not in explanation["confidence"].get("value", "").casefold()


def test_success_signal_policy_adjustment_is_explained_without_score_change():
    events = [
        {
            "timestamp": BASE + timedelta(seconds=index),
            "source_ip": "198.51.100.44",
            "event_type": "authentication_failure",
            "username": "analyst",
            "occurrence_count": 1,
        }
        for index in range(5)
    ]
    events.append(
        {
            "timestamp": BASE + timedelta(seconds=6),
            "source_ip": "198.51.100.44",
            "event_type": "authentication_success",
            "username": "analyst",
            "occurrence_count": 1,
        }
    )
    alerts = [{"rule": "ssh_success_after_failures", "source_ip": "198.51.100.44"}]

    score = calculate_risk_scores(events, alerts)["198.51.100.44"]["score"]
    explanation = calculate_risk_explanations(events, alerts)["198.51.100.44"]

    assert score == 75
    assert explanation["score"] == score
    assert explanation["factors"]["success_after_failures"]["contribution"] == 30
    assert explanation["policy_adjustment"]["floor_applied"] is True
    assert explanation["policy_adjustment"]["unconfirmed_cap_applied"] is False
