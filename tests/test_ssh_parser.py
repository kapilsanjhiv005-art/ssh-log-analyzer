"""Parser coverage for classic, Loghub-style, and journald SSH records."""

from datetime import datetime
from pathlib import Path

import pytest

from ssh_parser import parse_log_file, parse_log_line


def test_classic_syslog_auth_event_uses_datetime():
    event = parse_log_line(
        "Oct 19 09:30:00 host sshd[1008]: Failed password for analyst "
        "from 192.0.2.10 port 45000 ssh2",
        year=2026,
    )

    assert event is not None
    assert event["timestamp"] == datetime(2026, 10, 19, 9, 30)
    assert event["event_type"] == "authentication_failure"
    assert event["source_port"] == 45000


def test_loghub_auth_and_metadata_formats():
    samples = [
        "Oct 19 09:30:00 host sshd[1008]: Failed password for invalid user guest "
        "from 198.51.100.2 port 22 ssh2",
        "Oct 19 09:30:01 host sshd[1008]: Invalid user guest from 198.51.100.2",
        "Oct 19 09:30:02 host sshd[1008]: Accepted publickey for analyst "
        "from 203.0.113.4 port 22 ssh2",
        "Oct 19 09:30:03 host sshd[1008]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.5 user=analyst",
        "Oct 19 09:30:04 host sshd[1008]: Connection closed by 192.0.2.9 [preauth]",
        "Oct 19 09:30:05 host sshd[1008]: Received disconnect from 192.0.2.8 port 22",
        "Oct 19 09:30:06 host sshd[1008]: reverse mapping checking getaddrinfo "
        "for example [192.0.2.7] POSSIBLE BREAK-IN ATTEMPT!",
    ]

    events = [parse_log_line(line, year=2026) for line in samples]

    assert all(events)
    assert events[0]["invalid_user"] is True
    assert events[1]["username"] == "guest"
    assert events[2]["event_type"] == "authentication_success"
    assert events[2]["source_ip"] == "203.0.113.4"
    assert events[2]["authentication_method"] == "publickey"
    assert events[3]["username"] == "analyst"
    assert events[4]["event_type"] == "connection_closed"
    assert events[5]["event_type"] == "connection_closed"
    assert events[6]["event_type"] == "suspicious_reverse_mapping"


def test_failed_publickey_is_a_weighted_authentication_failure():
    event = parse_log_line(
        "Oct 19 09:30:00 host sshd[1008]: Failed publickey for analyst "
        "from 192.0.2.10 port 45000 ssh2",
        year=2026,
    )

    assert event is not None
    assert event["event_type"] == "authentication_failure"
    assert event["authentication_method"] == "publickey"
    assert event["username"] == "analyst"
    assert event["occurrence_count"] == 1


def test_iso_timestamp_is_normalized_to_naive_utc():
    event = parse_log_line(
        "2026-10-19T12:30:00+03:00 host sshd[10]: Accepted password for analyst "
        "from 192.0.2.10 port 22 ssh2"
    )

    assert event["timestamp"] == datetime(2026, 10, 19, 9, 30)


def test_parser_handles_unicode_long_truncated_and_empty_username_inputs():
    unicode_event = parse_log_line(
        "Oct 19 09:30:00 host sshd[1]: Failed password for יעל from 192.0.2.10 port 22 ssh2",
        year=2026,
    )
    long_unrelated = "x" * 100_000
    truncated_auth = "Oct 19 09:30:00 host sshd[1]: Failed password for"
    empty_username = (
        "Oct 19 09:30:00 host sshd[1]: Failed password for  from 192.0.2.10 port 22 ssh2"
    )
    invalid_timestamp = "Feb 30 09:30:00 host sshd[1]: Failed password for user"

    assert unicode_event is not None
    assert unicode_event["username"] == "יעל"
    assert parse_log_line(long_unrelated, year=2026) is None
    assert parse_log_line(truncated_auth, year=2026) is None
    assert parse_log_line(empty_username, year=2026) is None
    assert parse_log_line(invalid_timestamp, year=2026) is None


def test_malformed_reason_classifies_iso_fields_and_repeated_counts(tmp_path):
    path = tmp_path / "edge-cases.log"
    path.write_text(
        "2026-13-01T09:30:00 host sshd[1]: Failed password for user "
        "from 192.0.2.10 port 22 ssh2\n"
        f"2026-10-19T09:30:00 host sshd[{'9' * 5000}]: Failed password for user "
        "from 192.0.2.10 port 22 ssh2\n"
        "Oct 19 09:30:00 host sshd[1]: message repeated 0 times: "
        "[ Failed password for user from 192.0.2.10 port 22 ssh2 ]\n"
        "Oct 19 09:30:00 host sshd[1]: Failed password for user "
        "from 999.999.999.999 port 22 ssh2\n"
        "Oct 19 09:30:00 host sshd[1]: Invalid user guest from not-an-ip\n"
        "Oct 19 09:30:00 host sshd[1]: pam_unix(sshd:auth): authentication failure; "
        "rhost=not-an-ip user=analyst\n"
        "Oct 19 09:30:00 host sshd[1]: pam_unix(sshd:auth): authentication failure; "
        "user=analyst\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    assert len(events) == 2
    assert all(event["event_type"] == "authentication_context" for event in events)
    assert stats["lines_malformed"] == 5
    assert stats["malformed_by_reason"] == {
        "invalid_timestamp": 1,
        "invalid_field_value": 1,
        "invalid_repeated_count": 1,
        "invalid_source_ip": 2,
    }


def test_parse_file_reports_coverage_and_december_january_rollover(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "Dec 31 23:59:59 host sshd[1]: Accepted password for analyst "
        "from 192.0.2.1 port 22 ssh2\n"
        "Jan  1 00:00:01 host sshd[2]: Accepted password for analyst "
        "from 192.0.2.1 port 22 ssh2\n"
        "not an ssh record\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2025)

    assert [event["timestamp"].year for event in events] == [2025, 2026]
    assert stats == {
        "lines_read": 3,
        "events_parsed": 2,
        "lines_ignored": 1,
        "lines_malformed": 0,
        "malformed_by_reason": {},
        "effective_event_occurrences": 2,
        "effective_authentication_attempts": 2,
        "authentication_context_records": 0,
        "authentication_context_categories": {},
        "parsed_record_categories": {"authentication_success": 2},
        "records_requiring_contextual_correlation": 0,
        "supporting_evidence_records": 0,
        "unattributed_contextual_records": 0,
        "records_without_direct_source_ip": 0,
        "unresolved_or_ambiguous_context_records": 0,
        "authentication_failures": 0,
        "password_authentication_failures": 0,
        "authentication_method_probes": 0,
        "authentication_successes": 2,
        "root_authentication_failures": 0,
        "root_password_authentication_failures": 0,
        "root_authentication_successes": 0,
    }


def test_parse_file_separates_ignored_and_malformed_lines(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_text(
        "Oct 19 09:30:00 host sshd[1]: Connection closed by 192.0.2.5 [preauth]\n"
        "Oct 19 09:30:01 host sshd[2]: Failed password for analyst from nowhere\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    assert len(events) == 1
    assert events[0]["event_type"] == "connection_closed"
    assert stats["events_parsed"] == 1
    assert stats["lines_ignored"] == 0
    assert stats["lines_malformed"] == 1


def test_malformed_reason_counts_and_bounded_line_number_samples(tmp_path):
    path = tmp_path / "malformed.log"
    path.write_text(
        "Feb 30 09:30:00 host sshd[1]: Failed password for root "
        "from 192.0.2.1 port 22 ssh2\n"
        "Oct 19 09:30:01 host sshd[2]: Failed password for root from nowhere\n"
        "Oct 19 09:30:02 host sshd[3]: message repeated 1000001 times: "
        "[ Failed password for root from 192.0.2.1 port 22 ssh2 ]\n"
        "unrecognized service message\n",
        encoding="utf-8",
    )

    _, stats = parse_log_file(path, year=2026, include_malformed_records=True)

    assert stats["malformed_by_reason"] == {
        "invalid_timestamp": 1,
        "invalid_source_ip": 1,
        "invalid_repeated_count": 1,
    }
    assert stats["lines_malformed"] == 3
    assert [row["line_number"] for row in stats["malformed_records"]] == [1, 2, 3]
    assert stats["malformed_records_truncated"] == 0

    many = tmp_path / "many-malformed.log"
    row = "Oct 19 09:30:01 host sshd[2]: Failed password for root from nowhere\n"
    many.write_text(row * 105, encoding="utf-8")
    _, bounded = parse_log_file(many, year=2026, include_malformed_records=True)
    assert bounded["lines_malformed"] == 105
    assert len(bounded["malformed_records"]) == 100
    assert bounded["malformed_records_truncated"] == 5


def test_malformed_syslog_date_is_skipped():
    assert (
        parse_log_line(
            "Feb 30 09:30:00 host sshd[1008]: Accepted password for analyst "
            "from 192.0.2.10 port 22 ssh2",
            year=2026,
        )
        is None
    )


@pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "sample_logs" / "OpenSSH_2k.log").is_file(),
    reason="optional local Loghub sample is not present",
)
def test_optional_loghub_sample_has_valid_parser_accounting():
    sample = Path(__file__).resolve().parents[1] / "sample_logs" / "OpenSSH_2k.log"
    events, stats = parse_log_file(sample, year=2016)
    assert events
    assert (
        stats["events_parsed"] + stats["lines_ignored"] + stats["lines_malformed"]
        == stats["lines_read"]
    )


def test_repeated_auth_message_is_parsed_as_weighted_occurrence():
    line = (
        "Oct 19 09:30:00 host sshd[1]: message repeated 5 times: "
        "[ Failed password for analyst from 192.0.2.10 port 22 ssh2 ]"
    )
    event = parse_log_line(line, year=2026)

    assert event is not None
    assert event["event_type"] == "authentication_failure"
    assert event["occurrence_count"] == 5
    assert event["source_ip"] == "192.0.2.10"


def test_repeated_auth_message_rejects_unbounded_count():
    line = (
        "Oct 19 09:30:00 host sshd[1]: message repeated 1000001 times: "
        "[ Failed password for analyst from 192.0.2.10 port 22 ssh2 ]"
    )
    assert parse_log_line(line, year=2026) is None

    enormous = line.replace("1000001", "9" * 5000)
    assert parse_log_line(enormous, year=2026) is None


def test_repeated_auth_weights_accept_boundaries_without_expanding_records(tmp_path):
    path = tmp_path / "repeat-boundaries.log"
    path.write_text(
        "Oct 19 09:30:00 host sshd[1]: Failed password for analyst "
        "from 192.0.2.10 port 22 ssh2\n"
        "Oct 19 09:30:01 host sshd[1]: message repeated 1 times: "
        "[ Failed password for analyst from 192.0.2.10 port 22 ssh2 ]\n"
        "Oct 19 09:30:02 host sshd[2]: message repeated 1000000 times: "
        "[ Failed publickey for analyst from 192.0.2.11 port 22 ssh2 ]\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    assert stats["events_parsed"] == 3
    assert [event["occurrence_count"] for event in events] == [1, 1, 1_000_000]
    assert stats["authentication_failures"] == 1_000_002
    assert stats["effective_authentication_attempts"] == 1_000_002
    assert len(events) == 3


def test_ssh_parser_rejects_unbounded_numeric_fields_without_crashing():
    giant = "9" * 5000
    port_line = (
        f"Oct 19 09:30:00 host sshd[1]: Failed password for root from 192.0.2.1 port {giant} ssh2"
    )
    pid_line = (
        f"Oct 19 09:30:00 host sshd[{giant}]: Failed password for root from 192.0.2.1 port 22 ssh2"
    )

    assert parse_log_line(port_line, year=2026) is None
    assert parse_log_line(pid_line, year=2026) is None


def test_parse_file_counts_repeated_malformed_and_ignored_lines(tmp_path):
    path = tmp_path / "repeated.log"
    path.write_text(
        "Oct 19 09:30:00 host sshd[1]: Failed password for analyst from 192.0.2.10 port 22 ssh2\n"
        "Oct 19 09:30:01 host sshd[1]: message repeated 5 times: "
        "[ Failed password for analyst from 192.0.2.10 port 22 ssh2 ]\n"
        "Oct 19 09:30:02 host sshd[2]: Failed password for analyst from nowhere\n"
        "Oct 19 09:30:03 host systemd[1]: Started unrelated service\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    assert [item["occurrence_count"] for item in events] == [1, 5]
    assert sum(item["occurrence_count"] for item in events) == 6
    assert stats == {
        "lines_read": 4,
        "events_parsed": 2,
        "lines_ignored": 1,
        "lines_malformed": 1,
        "malformed_by_reason": {"invalid_source_ip": 1},
        "effective_event_occurrences": 6,
        "effective_authentication_attempts": 6,
        "authentication_context_records": 0,
        "authentication_context_categories": {},
        "parsed_record_categories": {"authentication_failure": 2},
        "records_requiring_contextual_correlation": 0,
        "supporting_evidence_records": 0,
        "unattributed_contextual_records": 0,
        "records_without_direct_source_ip": 0,
        "unresolved_or_ambiguous_context_records": 0,
        "authentication_failures": 6,
        "password_authentication_failures": 6,
        "authentication_method_probes": 0,
        "authentication_successes": 0,
        "root_authentication_failures": 0,
        "root_password_authentication_failures": 0,
        "root_authentication_successes": 0,
    }
