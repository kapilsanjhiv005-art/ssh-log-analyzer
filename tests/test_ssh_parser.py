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
    assert events[3]["username"] == "analyst"
    assert events[4]["event_type"] == "connection_closed"
    assert events[5]["event_type"] == "connection_closed"
    assert events[6]["event_type"] == "suspicious_reverse_mapping"


def test_iso_timestamp_is_normalized_to_naive_utc():
    event = parse_log_line(
        "2026-10-19T12:30:00+03:00 host sshd[10]: Accepted password for analyst "
        "from 192.0.2.10 port 22 ssh2"
    )

    assert event["timestamp"] == datetime(2026, 10, 19, 9, 30)


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
    }


def test_parse_file_separates_ignored_and_malformed_lines(tmp_path):
    path = tmp_path / "mixed.log"
    path.write_text(
        "Oct 19 09:30:00 host sshd[1]: Connection closed by 192.0.2.5 [preauth]\n"
        "Oct 19 09:30:01 host sshd[2]: Failed password for analyst from nowhere\n",
        encoding="utf-8",
    )

    events, stats = parse_log_file(path, year=2026)

    assert events == []
    assert stats["events_parsed"] == 0
    assert stats["lines_ignored"] == 1
    assert stats["lines_malformed"] == 1


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
