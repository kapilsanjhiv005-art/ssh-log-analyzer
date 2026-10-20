"""Configurable SSH low-and-slow detection regression tests."""

import ipaddress
from datetime import datetime, timedelta

import pytest

from config import load_config, validate_config
from detections import analyze_events, detect_low_and_slow_bruteforce

BASE = datetime(2026, 10, 19, 9, 0)
SOURCE_IP = "198.51.100.70"


def _event(second: int, *, occurrences: int = 1) -> dict:
    """Create a documentation-range SSH failure for a synthetic timeline."""
    return {
        "timestamp": BASE + timedelta(seconds=second),
        "source_ip": SOURCE_IP,
        "username": "analyst",
        "event_type": "authentication_failure",
        "invalid_user": False,
        "is_root": False,
        "occurrence_count": occurrences,
    }


def _enabled_config(**overrides):
    """Enable low-and-slow using defaults with optional validation cases."""
    config = load_config(None)
    config["low_and_slow"].update({"enabled": True, **overrides})
    return config


def test_low_and_slow_detects_weighted_failures_spaced_beyond_short_window():
    events = [_event(hour * 3600) for hour in range(20)]

    result = analyze_events(events, config=_enabled_config())
    alert = next(item for item in result["alerts"] if item["rule"] == "ssh_low_and_slow_bruteforce")

    assert {item["rule"] for item in result["alerts"]} == {"ssh_low_and_slow_bruteforce"}
    assert alert["attempt_count"] == 20
    assert alert["window_seconds"] == 86400
    assert alert["severity"] == alert["base_severity"] == "Medium"
    assert alert["mitre_attack_id"] == "T1110.001"
    assert alert["source_ip"] == SOURCE_IP
    assert result["risk_scores"][SOURCE_IP]


def test_low_and_slow_is_disabled_by_default_and_below_threshold():
    events = [_event(hour * 3600) for hour in range(20)]
    assert load_config(None)["low_and_slow"]["enabled"] is False
    assert not any(
        alert["rule"] == "ssh_low_and_slow_bruteforce" for alert in analyze_events(events)["alerts"]
    )
    assert detect_low_and_slow_bruteforce(events[:19], threshold=20) == []


def test_low_and_slow_does_not_join_events_outside_its_long_window():
    events = [_event(index * 90 * 60) for index in range(20)]

    assert detect_low_and_slow_bruteforce(events, threshold=20) == []


def test_low_and_slow_excludes_activity_that_reaches_short_bruteforce_threshold():
    events = [_event(second) for second in range(5)]
    events.extend(_event(hour * 3600) for hour in range(1, 16))

    alerts = analyze_events(events, config=_enabled_config())["alerts"]

    assert "ssh_brute_force" in {alert["rule"] for alert in alerts}
    assert "ssh_low_and_slow_bruteforce" not in {alert["rule"] for alert in alerts}


def test_low_and_slow_counts_repeated_occurrences_without_expanding_records():
    events = [_event(hour * 2 * 3600, occurrences=2) for hour in range(10)]

    alert = detect_low_and_slow_bruteforce(events, threshold=20)[0]

    assert len(events) == 10
    assert alert["attempt_count"] == 20


def test_low_and_slow_respects_existing_cidr_allowlist():
    events = [_event(hour * 3600) for hour in range(20)]
    networks = [ipaddress.ip_network("198.51.100.0/24")]

    assert detect_low_and_slow_bruteforce(events, allowlist=networks) == []


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"enabled": "yes"}, "enabled must be a boolean"),
        ({"threshold": 0}, "positive integer"),
        (
            {"enabled": True, "window_seconds": 60},
            "greater than brute_force.window_seconds",
        ),
    ],
)
def test_low_and_slow_configuration_rejects_invalid_values(tmp_path, override, message):
    config = tmp_path / "low-and-slow.yaml"
    lines = ["low_and_slow:"]
    lines.extend(f"  {key}: {value!r}".lower() for key, value in override.items())
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_config(config)


def test_disabled_low_and_slow_does_not_restrict_existing_bruteforce_window_config():
    """An inactive optional detector does not constrain existing CLI settings."""
    config = load_config(None)
    config["brute_force"]["window_seconds"] = 86400

    assert validate_config(config)["brute_force"]["window_seconds"] == 86400
