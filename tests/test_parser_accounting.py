"""Accounting invariants for physical SSH log lines and weighted events."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from ssh_parser import parse_log_file

ROOT = Path(__file__).parents[1]
REPEATED_FIXTURE = ROOT / "sample_logs" / "repeated_syslog_semantics.log"


def _assert_line_partition(stats: dict[str, int], expected: tuple[int, int, int, int]) -> None:
    """Assert lines read partition into retained auth records, ignored, malformed."""
    lines_read, parsed_records, ignored_lines, malformed_lines = expected
    assert stats["lines_read"] == lines_read
    assert stats["events_parsed"] == parsed_records
    assert stats["lines_ignored"] == ignored_lines
    assert stats["lines_malformed"] == malformed_lines
    assert parsed_records + ignored_lines + malformed_lines == lines_read
    assert sum(stats["malformed_by_reason"].values()) == malformed_lines


def test_mixed_ssh_input_separates_lines_records_occurrences_and_outcomes(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_text(
        "Oct 19 09:00:00 host sshd[1]: Failed password for root "
        "from 192.0.2.10 port 22 ssh2\n"
        "Oct 19 09:00:01 host sshd[2]: Accepted publickey for analyst "
        "from 192.0.2.11 port 22 ssh2\n"
        "Oct 19 09:00:02 host sshd[3]: Connection closed by 192.0.2.12 [preauth]\n"
        "Oct 19 09:00:03 host sshd[4]: Failed password for user from nowhere\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    _assert_line_partition(stats, (4, 3, 0, 1))
    assert sum(event["occurrence_count"] for event in events) == 3
    assert stats["effective_event_occurrences"] == 3
    assert stats["authentication_failures"] == 1
    assert stats["authentication_successes"] == 1
    assert stats["root_authentication_failures"] == 1
    assert stats["root_authentication_successes"] == 0
    assert Counter(event["event_type"] for event in events) == {
        "authentication_failure": 1,
        "authentication_success": 1,
        "connection_closed": 1,
    }
    assert (
        sum(
            event["occurrence_count"]
            for event in events
            if event["event_type"] == "authentication_failure"
        )
        == 1
    )
    assert (
        sum(
            event["occurrence_count"]
            for event in events
            if event.get("is_root") and event["event_type"] == "authentication_failure"
        )
        == 1
    )


def test_repeated_summary_preserves_physical_line_and_weighted_event_counts():
    events, stats = parse_log_file(REPEATED_FIXTURE, year=2026)

    _assert_line_partition(stats, (2, 2, 0, 0))
    assert [event["occurrence_count"] for event in events] == [1, 4]
    assert sum(event["occurrence_count"] for event in events) == 5
    assert stats["effective_event_occurrences"] == 5
    assert stats["authentication_failures"] == 5
    assert stats["authentication_successes"] == 0
    assert stats["root_authentication_failures"] == 5
    assert stats["root_authentication_successes"] == 0
    assert all(event["event_type"] == "authentication_failure" for event in events)
    assert sum(event["occurrence_count"] for event in events if event["is_root"]) == 5


def test_empty_input_has_zero_accounting(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("", encoding="utf-8")

    events, stats = parse_log_file(path, year=2026)

    _assert_line_partition(stats, (0, 0, 0, 0))
    assert events == []


def test_only_ignored_non_authentication_records_are_not_retained_as_events(tmp_path):
    path = tmp_path / "ignored.log"
    path.write_text(
        "Oct 19 09:00:00 host sshd[1]: Connection closed by 192.0.2.12 [preauth]\n"
        "Oct 19 09:00:01 systemd[1]: Started unrelated service\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    _assert_line_partition(stats, (2, 1, 1, 0))
    assert [event["event_type"] for event in events] == ["connection_closed"]


def test_only_malformed_authentication_records_are_accounted_as_malformed(tmp_path):
    path = tmp_path / "malformed.log"
    path.write_text(
        "Oct 19 09:00:00 host sshd[1]: Failed password for root from nowhere\n"
        "Oct 19 09:00:01 host sshd[2]: Accepted password for analyst from 999.0.0.1\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    _assert_line_partition(stats, (2, 0, 0, 2))
    assert events == []


def test_authentication_attempts_use_terminal_outcomes_and_keep_context(tmp_path):
    """Exercise terminal attempt counts, contextual evidence, repeats, and parser scope."""
    path = tmp_path / "attempt-accounting.log"
    path.write_text(
        "Oct 19 09:00:00 node-a sshd[10]: Invalid user guest from 192.0.2.10\n"
        "Oct 19 09:00:01 node-a sshd[10]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.10 user=guest\n"
        "Oct 19 09:00:02 node-a sshd[10]: Failed password for invalid user guest "
        "from 192.0.2.10 port 44000 ssh2\n"
        "Oct 19 09:00:03 node-a sshd[10]: Failed publickey for root "
        "from 192.0.2.10 port 44000 ssh2\n"
        "Oct 19 09:00:04 node-a sshd[10]: message repeated 2 times: "
        "[ Failed password for root from 192.0.2.10 port 44000 ssh2 ]\n"
        "Oct 19 09:00:05 node-a sshd[11]: input_userauth_request: invalid user probe [preauth]\n"
        "Oct 19 09:00:06 node-a sshd[11]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=client.example user=probe\n"
        "Oct 19 09:00:07 node-a sshd[12]: Failed password for guest "
        "from 198.51.100.12 port 44001 ssh2\n"
        "Oct 19 09:00:08 node-a sshd[13]: Accepted password for guest "
        "from 198.51.100.12 port 44001 ssh2\n"
        "Oct 19 09:00:09 node-a sshd[14]: Accepted publickey for admin "
        "from 203.0.113.14 port 44002 ssh2\n"
        "Oct 19 09:00:10 node-a sshd[15]: Connection closed by 203.0.113.15 [preauth]\n"
        "Oct 19 09:00:11 node-a sshd[16]: Did not receive identification string from 203.0.113.16\n"
        "Oct 19 09:00:12 node-a sshd[17]: Failed password for guest from nowhere\n"
        "Oct 19 09:00:13 node-a sshd[18]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=client.example user=unlinked\n"
        "Oct 19 09:00:14 node-a sshd[19]: Failed password for guest "
        "from 203.0.113.19 port 44003 ssh2\n"
        "Oct 19 09:00:25 node-a sshd[19]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.19 user=guest\n"
        "genuinely malformed input\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026, include_malformed_records=True)

    assert stats["lines_read"] == 17
    assert (
        stats["lines_read"]
        == stats["events_parsed"] + stats["lines_ignored"] + stats["lines_malformed"]
    )
    assert stats["lines_malformed"] == 1
    assert stats["lines_ignored"] == 1
    assert stats["authentication_failures"] == 6
    assert stats["authentication_successes"] == 2
    assert stats["root_authentication_failures"] == 3
    assert stats["root_authentication_successes"] == 0
    assert stats["authentication_context_records"] == 6
    assert stats["records_requiring_contextual_correlation"] == 6
    assert stats["unattributed_contextual_records"] == 3
    assert stats["supporting_evidence_records"] == 2
    assert stats["effective_authentication_attempts"] == 8
    assert (
        sum(
            event["occurrence_count"]
            for event in events
            if event["event_type"] == "authentication_failure"
        )
        == 6
    )
    assert (
        sum(
            event["occurrence_count"]
            for event in events
            if event["event_type"] == "authentication_success"
        )
        == 2
    )
    assert [
        event["source_ip"] for event in events if event["event_type"] == "authentication_failure"
    ] == [
        "192.0.2.10",
        "192.0.2.10",
        "192.0.2.10",
        "198.51.100.12",
        "203.0.113.19",
    ]
    assert all(
        len(event["supporting_evidence"]) == 2
        for event in events
        if event.get("event_type") == "authentication_failure"
        and event.get("username") == "guest"
        and event.get("source_ip") == "192.0.2.10"
    )
    eleven_second_context = next(event for event in events if event.get("_event_id") == "ssh:16")
    assert eleven_second_context["event_type"] == "authentication_context"
    assert "correlated_attempt_id" not in eleven_second_context
    from detections import correlate_incidents, detect_brute_force, detect_root_attempts

    brute_alert = next(
        alert
        for alert in detect_brute_force(events, threshold=1)
        if alert["source_ip"] == "192.0.2.10"
    )
    root_alert = next(
        alert
        for alert in detect_root_attempts(events, minimum_attempts=1)
        if alert["source_ip"] == "192.0.2.10"
    )
    assert len(brute_alert["supporting_evidence"]) == 2
    assert brute_alert["attempt_count"] == 4
    assert root_alert["attempt_count"] == 3
    incident = next(
        item
        for item in correlate_incidents([brute_alert, root_alert])
        if item["source_ip"] == "192.0.2.10"
    )
    assert len(incident["supporting_evidence"]) == 2
    assert incident["attempt_count"] == 4
    assert set(incident["evidence_event_ids"]) == {
        "ssh:1",
        "ssh:2",
        "ssh:3",
        "ssh:4",
        "ssh:5",
    }
    from analyzer import render_csv
    from html_report import render_html_report
    from markdown_report import render_markdown_report

    result = {
        "alerts": [brute_alert, root_alert],
        "incidents": [incident],
        "risk_scores": {},
        "parse_stats": stats,
        "alerts_suppressed": 0,
    }
    assert "supporting_evidence" in render_csv([brute_alert]).splitlines()[0]
    assert "invalid_user" in render_csv([brute_alert]).splitlines()[1]
    assert "Supporting authentication context" in render_html_report(events, result)
    assert "Supporting authentication context" in render_markdown_report(result)
    assert any(
        event.get("source_ip") is None and event["event_type"] == "authentication_context"
        for event in events
    )
    assert all(event["source_ip"] != "client.example" for event in events)


def test_parser_retains_valid_auth_context_without_terminal_outcome(tmp_path):
    path = tmp_path / "context-only.log"
    path.write_text(
        "Oct 19 09:00:00 node-a sshd[10]: input_userauth_request: invalid user probe [preauth]\n"
        "Oct 19 09:00:01 node-a sshd[10]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=client.example user=probe\n"
        "Oct 19 09:00:02 node-a sshd[11]: Connection closed by 192.0.2.20 [preauth]\n"
        "Oct 19 09:00:03 node-a sshd[12]: Did not receive identification string from 192.0.2.21\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    assert stats["lines_read"] == 4
    assert stats["events_parsed"] == 4
    assert stats["lines_ignored"] == stats["lines_malformed"] == 0
    assert stats["authentication_failures"] == stats["authentication_successes"] == 0
    assert stats["authentication_context_records"] == 2
    assert stats["unattributed_contextual_records"] == 2
    assert {event["event_type"] for event in events} == {
        "authentication_context",
        "connection_closed",
        "identification_missing",
    }


def test_hostname_rhost_is_attributed_only_with_unique_pid_user_time_match(tmp_path):
    path = tmp_path / "correlated-hostname-context.log"
    path.write_text(
        "Oct 19 09:00:00 node-a sshd[90]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=client.example user=analyst\n"
        "Oct 19 09:00:10 node-a sshd[90]: Accepted password for analyst "
        "from 192.0.2.90 port 44000 ssh2\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)
    context = next(event for event in events if event["event_type"] == "authentication_context")
    success = next(event for event in events if event["event_type"] == "authentication_success")

    assert stats["effective_authentication_attempts"] == 1
    assert stats["authentication_failures"] == 0
    assert stats["authentication_successes"] == 1
    assert stats["supporting_evidence_records"] == 1
    assert stats["unattributed_contextual_records"] == 0
    assert context["source_ip"] == "192.0.2.90"
    assert context["source_attribution"] == "correlated"
    assert context["correlated_attempt_id"] == success["_event_id"]
    assert success["supporting_evidence"][0]["source_ip"] == "192.0.2.90"


def test_auth_context_boundary_and_ambiguous_matches_are_conservative(tmp_path):
    exact = tmp_path / "exact-boundary.log"
    exact.write_text(
        "Oct 19 09:00:00 node-a sshd[91]: Invalid user guest from 198.51.100.91\n"
        "Oct 19 09:00:10 node-a sshd[91]: Failed password for invalid user guest "
        "from 198.51.100.91 port 44001 ssh2\n",
        encoding="utf-8",
    )
    exact_events, exact_stats = parse_log_file(exact, year=2026)
    exact_context = next(
        event for event in exact_events if event["event_type"] == "authentication_context"
    )
    assert exact_stats["supporting_evidence_records"] == 1
    assert exact_stats["unresolved_or_ambiguous_context_records"] == 0
    assert exact_context["correlated_attempt_id"] == "ssh:2"

    ambiguous = tmp_path / "ambiguous.log"
    ambiguous.write_text(
        "Oct 19 09:00:00 node-a sshd[92]: Invalid user guest from 198.51.100.92\n"
        "Oct 19 09:00:05 node-a sshd[92]: Failed password for invalid user guest "
        "from 198.51.100.92 port 44002 ssh2\n"
        "Oct 19 09:00:06 node-a sshd[92]: Failed publickey for invalid user guest "
        "from 198.51.100.92 port 44002 ssh2\n",
        encoding="utf-8",
    )
    ambiguous_events, ambiguous_stats = parse_log_file(ambiguous, year=2026)

    assert ambiguous_stats["authentication_failures"] == 2
    assert ambiguous_stats["effective_authentication_attempts"] == 2
    assert ambiguous_stats["supporting_evidence_records"] == 0
    assert ambiguous_stats["unresolved_or_ambiguous_context_records"] == 1
    assert all("supporting_evidence" not in event for event in ambiguous_events)

    mismatched = tmp_path / "mismatched-context.log"
    mismatched.write_text(
        "Oct 19 09:00:00 node-a sshd[93]: Invalid user guest from 192.0.2.93\n"
        "Oct 19 09:00:01 node-b sshd[93]: Failed password for invalid user guest "
        "from 192.0.2.93 port 44003 ssh2\n"
        "Oct 19 09:00:10 node-a sshd[94]: Invalid user guest from 192.0.2.93\n"
        "Oct 19 09:00:11 node-a sshd[94]: Failed password for invalid user guest "
        "from 198.51.100.94 port 44004 ssh2\n",
        encoding="utf-8",
    )
    mismatch_events, mismatch_stats = parse_log_file(mismatched, year=2026)

    assert mismatch_stats["authentication_failures"] == 2
    assert mismatch_stats["supporting_evidence_records"] == 0
    assert mismatch_stats["unresolved_or_ambiguous_context_records"] == 2
    assert all(
        "correlated_attempt_id" not in event
        for event in mismatch_events
        if event["event_type"] == "authentication_context"
    )


def test_failed_none_is_separately_accounted_from_password_failures(tmp_path):
    path = tmp_path / "method-probes.log"
    path.write_text(
        "Oct 19 09:00:00 host sshd[1]: Failed password for root "
        "from 192.0.2.10 port 22 ssh2\n"
        "Oct 19 09:00:01 host sshd[2]: Failed none for root "
        "from 192.0.2.10 port 22 ssh2\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    assert stats["authentication_failures"] == 2
    assert stats["password_authentication_failures"] == 1
    assert stats["authentication_method_probes"] == 1
    assert stats["root_authentication_failures"] == 2
    assert stats["root_password_authentication_failures"] == 1
    assert [event["authentication_method"] for event in events] == ["password", "none"]


def test_invalid_user_context_tolerates_repeated_whitespace(tmp_path):
    path = tmp_path / "invalid-user-spacing.log"
    path.write_text(
        "Dec 10 08:24:32 LabSZ sshd[24361]: Invalid user  0101 from 5.188.10.180\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2016, include_malformed_records=True)

    assert stats["lines_malformed"] == 0
    assert stats["events_parsed"] == 1
    assert events[0]["event_type"] == "authentication_context"
    assert events[0]["username"] == "0101"
    assert events[0]["source_ip"] == "5.188.10.180"


def test_context_event_categories_distinguish_invalid_user_pam_and_sshd_requests(tmp_path):
    path = tmp_path / "context-categories.log"
    path.write_text(
        "Oct 19 09:00:00 host sshd[1]: Invalid user guest from 192.0.2.10\n"
        "Oct 19 09:00:01 host sshd[1]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=client.example user=guest\n"
        "Oct 19 09:00:02 host sshd[1]: input_userauth_request: invalid user guest [preauth]\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    assert stats["authentication_context_categories"] == {
        "invalid_user": 1,
        "pam_authentication_failure": 1,
        "input_userauth_request": 1,
    }
    assert stats["parsed_record_categories"]["authentication_context"] == 3
    assert [event["context_kind"] for event in events] == [
        "invalid_user",
        "pam_authentication_failure",
        "input_userauth_request",
    ]
