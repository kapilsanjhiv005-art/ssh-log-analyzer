"""Aggregation, correlation, scoring, configuration, and new-rule tests."""

from datetime import datetime, timedelta

import pytest

from config import is_allowlisted, load_allowlist, load_config
from detections import (
    analyze_events,
    calculate_risk_scores,
    correlate_incidents,
    detect_brute_force,
    detect_distributed_bruteforce,
    detect_new_source_ip_login,
    detect_off_hours_login,
    detect_password_spraying,
    detect_root_attempts,
    detect_success_after_failures,
    detect_username_enumeration,
    merge_adjacent_alerts,
    risk_band,
)

BASE = datetime(2026, 10, 19, 9, 0)


def event(
    seconds=0,
    *,
    ip="198.51.100.10",
    username="analyst",
    kind="authentication_failure",
    invalid=False,
):
    return {
        "timestamp": BASE + timedelta(seconds=seconds),
        "hostname": "test",
        "process_id": 1000,
        "username": username,
        "source_ip": ip,
        "source_port": 22,
        "event_type": kind,
        "invalid_user": invalid,
        "is_root": username == "root",
    }


def test_root_attempts_are_aggregated_with_standard_alert_fields():
    alerts = detect_root_attempts([event(i * 10, username="root") for i in range(3)])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["attempt_count"] == 3
    assert alert["base_severity"] == alert["severity"] == "Low"
    assert alert["first_seen"] == BASE
    assert alert["last_seen"] == BASE + timedelta(seconds=20)
    assert alert["usernames_targeted"] == ["root"]
    assert all(
        key in alert
        for key in (
            "rule",
            "severity",
            "source_ip",
            "first_seen",
            "last_seen",
            "attempt_count",
            "usernames_targeted",
            "description",
            "mitre_attack_id",
            "mitre_technique_name",
            "recommended_action",
        )
    )


def test_incidents_group_overlapping_rules_and_escalate_success_after_failures():
    alerts = [
        {
            "rule": "ssh_brute_force",
            "severity": "Medium",
            "source_ip": "198.51.100.10",
            "first_seen": BASE,
            "last_seen": BASE + timedelta(seconds=30),
        },
        {
            "rule": "ssh_password_spraying",
            "severity": "Medium",
            "source_ip": "198.51.100.10",
            "first_seen": BASE + timedelta(seconds=10),
            "last_seen": BASE + timedelta(seconds=40),
        },
        {
            "rule": "ssh_success_after_failures",
            "severity": "High",
            "source_ip": "198.51.100.10",
            "first_seen": BASE + timedelta(seconds=20),
            "last_seen": BASE + timedelta(seconds=45),
        },
    ]
    incidents = correlate_incidents(alerts)
    assert len(incidents) == 1
    assert incidents[0]["combined_severity"] == "High"
    assert incidents[0]["contributing_rules"] == [
        "ssh_brute_force",
        "ssh_password_spraying",
        "ssh_success_after_failures",
    ]


def test_incidents_use_composite_risk_band_without_overwriting_base_severity():
    ip = "198.51.100.86"
    alerts = [
        {
            "rule": "ssh_root_login_attempt",
            "severity": "Low",
            "base_severity": "Low",
            "source_ip": ip,
            "first_seen": BASE,
            "last_seen": BASE + timedelta(seconds=2),
        },
        {
            "rule": "ssh_off_hours_login",
            "severity": "Low",
            "base_severity": "Low",
            "source_ip": ip,
            "first_seen": BASE + timedelta(seconds=1),
            "last_seen": BASE + timedelta(seconds=3),
        },
    ]
    incidents = correlate_incidents(alerts, {ip: {"score": 86, "band": "Critical"}})

    assert len(incidents) == 1
    assert incidents[0]["combined_severity"] == "Critical"
    assert incidents[0]["risk_score"] == 86
    assert incidents[0]["risk_band"] == "Critical"
    assert [alert["base_severity"] for alert in alerts] == ["Low", "Low"]
    assert [alert["severity"] for alert in alerts] == ["Low", "Low"]


def test_incidents_escalate_low_to_medium_when_success_rule_is_present():
    incident = correlate_incidents(
        [
            {
                "rule": "ssh_root_login_attempt",
                "severity": "Low",
                "source_ip": "198.51.100.2",
                "first_seen": BASE,
                "last_seen": BASE + timedelta(seconds=2),
            },
            {
                "rule": "ssh_success_after_failures",
                "severity": "Low",
                "source_ip": "198.51.100.2",
                "first_seen": BASE,
                "last_seen": BASE + timedelta(seconds=3),
            },
        ]
    )[0]
    assert incident["combined_severity"] == "Medium"


def test_distributed_bruteforce_positive_below_window_and_allowlist():
    five = [event(i, ip=f"198.51.100.{i + 1}", username="admin") for i in range(5)]
    alert = detect_distributed_bruteforce(five)[0]
    assert alert["rule"] == "ssh_distributed_bruteforce"
    assert alert["distinct_source_ips"] == 5
    assert detect_distributed_bruteforce(five[:4]) == []
    outside = [event(i * 180, ip=f"198.51.100.{i + 1}", username="admin") for i in range(5)]
    assert detect_distributed_bruteforce(outside) == []
    assert (
        detect_distributed_bruteforce(five, allowlist=load_allowlist_from("198.51.100.0/24")) == []
    )


def test_off_hours_login_positive_business_hours_and_recent_failure_severity():
    login = event(-7 * 3600, kind="authentication_success")
    assert detect_off_hours_login([login])[0]["severity"] == "Low"
    assert detect_off_hours_login([event(0, kind="authentication_success")]) == []
    assert detect_off_hours_login([login], business_start="00:00", business_end="23:59") == []
    with_failure = [event(-7 * 3600 - 10, ip=login["source_ip"]), login]
    assert detect_off_hours_login(with_failure)[0]["severity"] == "Medium"
    assert detect_off_hours_login([login], allowlist=load_allowlist_from("198.51.100.0/24")) == []


def test_new_source_login_requires_allowlist_and_aggregates_successes():
    login = event(0, ip="198.51.100.10", kind="authentication_success")
    assert detect_new_source_ip_login([login]) == []
    assert len(detect_new_source_ip_login([login], [])) == 1
    trusted = load_allowlist_from("192.0.2.0/24")
    assert (
        len(
            detect_new_source_ip_login(
                [login, event(10, ip=login["source_ip"], kind="authentication_success")], trusted
            )
        )
        == 1
    )
    assert (
        detect_new_source_ip_login(
            [event(0, ip="192.0.2.5", kind="authentication_success")], trusted
        )
        == []
    )
    separated = [login, event(2 * 86400, ip=login["source_ip"], kind="authentication_success")]
    assert len(detect_new_source_ip_login(separated, trusted)) == 2


def test_new_source_login_trusts_configured_ipv4_and_ipv6_loopback_only():
    allowlist = []
    for ip in ("127.0.0.1", "::1"):
        assert (
            detect_new_source_ip_login([event(ip=ip, kind="authentication_success")], allowlist)
            == []
        )
    external_login = event(ip="198.51.100.44", kind="authentication_success")
    assert len(detect_new_source_ip_login([external_login], allowlist)) == 1


def test_loopback_trust_is_new_source_specific_and_configurable(tmp_path):
    local_failures = [event(i, ip="127.0.0.1") for i in range(5)]
    result = analyze_events(local_failures, allowlist=[])
    assert any(alert["rule"] == "ssh_brute_force" for alert in result["alerts"])
    assert not any(alert["rule"] == "ssh_new_source_ip_login" for alert in result["alerts"])

    config_path = tmp_path / "config.yaml"
    config_path.write_text("new_source_ip:\n  trusted_local_sources: []\n", encoding="utf-8")
    configured = load_config(config_path)
    login = event(0, ip="127.0.0.1", kind="authentication_success")
    assert (
        len(
            detect_new_source_ip_login(
                [login], [], configured["new_source_ip"]["trusted_local_sources"]
            )
        )
        == 1
    )


def test_allowlisted_ip_suppresses_brute_and_root_alerts():
    trusted = load_allowlist_from("198.51.100.0/24")
    events = [event(i, username="root") for i in range(5)]
    assert detect_brute_force(events, allowlist=trusted) == []
    assert detect_root_attempts(events, allowlist=trusted) == []
    assert analyze_events(events, allowlist=trusted)["alerts_suppressed"] >= 1


def test_spraying_and_enumeration_below_window_and_allowlist_cases():
    users = ["analyst", "admin", "backup", "developer", "guest"]
    spray = [event(i * 5, username=user) for i, user in enumerate(users)]
    assert len(detect_password_spraying(spray)) == 1
    assert detect_password_spraying(spray[:4]) == []
    assert (
        detect_password_spraying([event(i * 70, username=user) for i, user in enumerate(users)])
        == []
    )
    trusted = load_allowlist_from("198.51.100.0/24")
    assert detect_password_spraying(spray, allowlist=trusted) == []

    invalid = [event(i * 5, username=f"bad{i}", invalid=True) for i in range(4)]
    assert len(detect_username_enumeration(invalid)) == 1
    assert detect_username_enumeration(invalid[:3]) == []
    assert (
        detect_username_enumeration(
            [event(i * 70, username=f"bad{i}", invalid=True) for i in range(4)]
        )
        == []
    )
    assert detect_username_enumeration(invalid, allowlist=trusted) == []


def test_root_and_success_after_failures_below_window_and_allowlist_cases():
    root_failures = [event(0, username="root"), event(120, username="root")]
    assert detect_root_attempts(root_failures) == []
    assert (
        detect_root_attempts([event(i, username="root") for i in range(3)])[0]["attempt_count"] == 3
    )
    trusted = load_allowlist_from("198.51.100.0/24")
    assert detect_root_attempts(root_failures, allowlist=trusted) == []

    too_few = [event(i, username="admin") for i in range(4)]
    too_few.append(event(10, username="admin", kind="authentication_success"))
    assert detect_success_after_failures(too_few) == []
    old_failures = [event(i * 400, username="admin") for i in range(5)]
    old_failures.append(event(2100, username="admin", kind="authentication_success"))
    assert detect_success_after_failures(old_failures) == []
    qualifying = [event(i, ip="203.0.113.10", username="admin") for i in range(5)]
    qualifying.append(event(10, ip="203.0.113.10", username="admin", kind="authentication_success"))
    trusted_success = load_allowlist_from("203.0.113.0/24")
    assert detect_success_after_failures(qualifying, allowlist=trusted_success) == []
    result = analyze_events(qualifying, allowlist=trusted_success)
    assert result["alerts_suppressed"] >= 1


def test_risk_scores_are_bounded_and_success_signal_outscores_low_volume():
    events = [event(i, ip="198.51.100.10", username="admin") for i in range(6)]
    events.append(event(35, ip="198.51.100.10", username="admin", kind="authentication_success"))
    events.append(event(1000, ip="203.0.113.4", kind="authentication_success"))
    result = analyze_events(events)
    scores = result["risk_scores"]
    assert scores["198.51.100.10"]["score"] > scores["203.0.113.4"]["score"]
    assert all(
        alert["severity"] == alert["base_severity"]
        and alert["risk_score"] == alert["source_risk_score"]
        and alert["risk_band"] == alert["source_risk_band"]
        for alert in result["alerts"]
    )
    assert all(0 <= risk["score"] <= 100 for risk in scores.values())
    assert calculate_risk_scores([], []) == {}


def test_risk_band_boundaries_and_success_after_failures_high_floor():
    assert [risk_band(score) for score in (0, 24, 25, 49, 50, 74, 75, 100)] == [
        "Low",
        "Low",
        "Medium",
        "Medium",
        "High",
        "High",
        "Critical",
        "Critical",
    ]
    ip = "198.51.100.60"
    scores = calculate_risk_scores(
        [event(ip=ip, kind="authentication_success")],
        [{"rule": "ssh_success_after_failures", "source_ip": ip}],
    )
    assert scores[ip]["score"] == 75
    assert scores[ip]["band"] == "Critical"


def test_adjacent_alert_merge_unions_unique_event_ids_and_keeps_separated_windows():
    first = {
        "rule": "ssh_brute_force",
        "source_ip": "198.51.100.10",
        "first_seen": BASE,
        "last_seen": BASE + timedelta(seconds=20),
        "attempt_count": 3,
        "_merge_event_ids": ["a", "b", "c"],
        "_merge_attempt_ids": ["a", "b", "c"],
        "usernames_targeted": ["analyst"],
        "window_seconds": 60,
        "description": "first",
        "recommended_action": "review",
    }
    second = {
        **first,
        "first_seen": BASE + timedelta(seconds=30),
        "last_seen": BASE + timedelta(seconds=50),
        "attempt_count": 3,
        "usernames_targeted": ["backup"],
        "_merge_event_ids": ["b", "c", "d"],
        "_merge_attempt_ids": ["b", "c", "d"],
    }
    separated = {
        **first,
        "first_seen": BASE + timedelta(minutes=5),
        "last_seen": BASE + timedelta(minutes=5),
        "_merge_event_ids": ["z"],
        "_merge_attempt_ids": ["z"],
    }
    merged = merge_adjacent_alerts([first, second, separated])
    assert len(merged) == 2
    assert merged[0]["attempt_count"] == 4
    assert merged[0]["unique_event_count"] == 4
    assert merged[0]["merged_alert_count"] == 2
    assert merged[0]["usernames_targeted"] == ["analyst", "backup"]
    assert merged[0]["recommended_action"] == "review"


def test_merge_gap_zero_empty_input_and_rule_ip_boundaries():
    def alert(rule, ip, start, end, identity):
        return {
            "rule": rule,
            "source_ip": ip,
            "first_seen": BASE + timedelta(seconds=start),
            "last_seen": BASE + timedelta(seconds=end),
            "attempt_count": 1,
            "_merge_event_ids": [identity],
            "_merge_attempt_ids": [identity],
            "usernames_targeted": [],
            "window_seconds": 60,
            "description": "test",
        }

    assert merge_adjacent_alerts([]) == []
    touching = [
        alert("ssh_brute_force", "192.0.2.20", 0, 10, "one"),
        alert("ssh_brute_force", "192.0.2.20", 10, 11, "two"),
    ]
    assert len(merge_adjacent_alerts(touching, merge_gap_seconds=0)) == 1
    separated = [touching[0], alert("ssh_brute_force", "192.0.2.20", 11, 12, "three")]
    assert len(merge_adjacent_alerts(separated, merge_gap_seconds=0)) == 2
    distinct = [
        touching[0],
        alert("ssh_brute_force", "192.0.2.21", 0, 10, "four"),
        alert("ssh_root_login_attempt", "192.0.2.20", 0, 10, "five"),
    ]
    assert len(merge_adjacent_alerts(distinct, merge_gap_seconds=60)) == 3


def test_root_minimum_attempts_below_at_and_above_threshold():
    assert detect_root_attempts([event(i, username="root") for i in range(2)]) == []
    at_threshold = detect_root_attempts([event(i, username="root") for i in range(3)])
    above_threshold = detect_root_attempts([event(i, username="root") for i in range(4)])
    assert at_threshold[0]["attempt_count"] == 3
    assert above_threshold[0]["attempt_count"] == 4


def test_risk_score_log_volume_separates_90_from_553_and_caps_unconfirmed():
    small_ip, large_ip = "198.51.100.11", "198.51.100.12"
    events = [event(i, ip=small_ip) for i in range(90)] + [
        event(i, ip=large_ip) for i in range(553)
    ]
    scores = calculate_risk_scores(events, [])
    assert scores[large_ip]["score"] > scores[small_ip]["score"]
    assert scores[large_ip]["score"] <= 74
    volume_scores = [
        calculate_risk_scores([event(i, ip="203.0.113.202") for i in range(count)], [])[
            "203.0.113.202"
        ]["score"]
        for count in (1, 10, 90, 553)
    ]
    assert volume_scores == sorted(volume_scores)


def test_risk_sort_breaks_ties_by_attempt_count_then_last_seen():
    events = (
        [event(i, ip="192.0.2.31", kind="authentication_success") for i in range(3)]
        + [event(i + 10, ip="192.0.2.32", kind="authentication_success") for i in range(3)]
        + [event(i, ip="192.0.2.33", kind="authentication_success") for i in range(4)]
    )
    assert list(calculate_risk_scores(events, [])) == ["192.0.2.33", "192.0.2.32", "192.0.2.31"]


def test_brute_force_severity_boundaries_and_sustained_description():
    for count, expected in ((49, "Medium"), (50, "High"), (51, "High"), (200, "High")):
        events = [event(i, ip="203.0.113.201") for i in range(count)]
        alert = analyze_events(events)["alerts"][0]
        assert alert["severity"] == expected
        if count == 200:
            assert "Sustained activity" in alert["description"]


def test_config_fallback_validation_and_cidr_allowlist(tmp_path):
    assert load_config(tmp_path / "missing.yaml")["distributed_bruteforce"]["ip_threshold"] == 5
    bad = tmp_path / "bad.yaml"
    bad.write_text("brute_force:\n  threshold: 0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="positive integer"):
        load_config(bad)
    bad.write_text("off_hours:\n  business_start: '25:00'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="valid time"):
        load_config(bad)
    cidrs = tmp_path / "trusted.txt"
    cidrs.write_text("# docs range\n192.0.2.0/24\n203.0.113.8\n", encoding="utf-8")
    trusted = load_allowlist(cidrs)
    assert len(trusted) == 2
    assert detect_root_attempts([event(username="root", ip="192.0.2.9")], allowlist=trusted) == []
    cidrs.write_text("not-an-ip\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid IP/CIDR"):
        load_allowlist(cidrs)
    bad_local = tmp_path / "bad-local.yaml"
    bad_local.write_text("new_source_ip:\n  trusted_local_sources: [bad-ip]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="trusted_local_sources entry"):
        load_config(bad_local)


def test_allowlist_matches_ipv4_ipv6_exact_and_cidr_and_handles_empty(tmp_path):
    path = tmp_path / "trusted.txt"
    path.write_text(
        "  # comments and surrounding whitespace are accepted\n"
        "  192.0.2.10  \n"
        "198.51.100.0/24\n"
        "2001:db8::10\n"
        "2001:db8:1::/48\n",
        encoding="utf-8",
    )
    networks = load_allowlist(path)
    assert len(networks) == 4
    assert is_allowlisted("192.0.2.10", networks)
    assert is_allowlisted("198.51.100.25", networks)
    assert is_allowlisted("2001:db8::10", networks)
    assert is_allowlisted("2001:db8:1::99", networks)
    assert not is_allowlisted("203.0.113.10", networks)
    assert not is_allowlisted("2001:db8:2::99", networks)
    assert not is_allowlisted("not-an-ip", networks)
    assert not is_allowlisted("192.0.2.10", [])

    path.write_text("# empty allowlist\n  \n", encoding="utf-8")
    assert load_allowlist(path) == []
    with pytest.raises(FileNotFoundError):
        load_allowlist(tmp_path / "missing.txt")


def load_allowlist_from(value):
    """Build a parsed network list through the standard loader without disk I/O."""
    import ipaddress

    return [ipaddress.ip_network(value)]


def test_repeated_event_occurrences_count_toward_thresholds_and_risk():
    repeated = event(0, ip="203.0.113.88")
    repeated["occurrence_count"] = 5

    result = analyze_events([repeated])

    brute = next(alert for alert in result["alerts"] if alert["rule"] == "ssh_brute_force")
    assert brute["attempt_count"] == 5
    assert "5 failed attempts" in brute["description"]
    assert result["risk_scores"]["203.0.113.88"]["score"] == 15


def test_overlapping_rule_incident_reports_deduplicated_evidence():
    events = [event(i, username=name) for i, name in enumerate(("a", "b", "c", "d", "e"))]
    for item in events:
        item["authentication_method"] = "password"

    result = analyze_events(events)
    incident = result["incidents"][0]

    assert incident["attempt_count"] == 5
    assert incident["usernames_targeted"] == ["a", "b", "c", "d", "e"]
    assert incident["authentication_methods"] == ["password"]
    assert all("_incident_event_counts" not in alert for alert in result["alerts"])


def test_repeated_failures_qualify_success_after_failures():
    repeated = event(0, ip="203.0.113.89", username="admin")
    repeated["occurrence_count"] = 5
    success = event(10, ip="203.0.113.89", username="admin", kind="authentication_success")

    result = analyze_events([repeated, success])

    alert = next(item for item in result["alerts"] if item["rule"] == "ssh_success_after_failures")
    assert alert["attempt_count"] == 5
    assert result["risk_scores"]["203.0.113.89"] == {"score": 75, "band": "Critical"}
