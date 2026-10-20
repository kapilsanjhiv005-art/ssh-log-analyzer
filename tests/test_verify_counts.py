"""Tests for the standalone raw-record root-count verifier."""

from tools.verify_counts import verify_counts


def test_raw_root_verification_breaks_down_methods_outcomes_and_repeats(tmp_path):
    log = tmp_path / "root.log"
    log.write_text(
        "Oct 19 09:00:00 host sshd[10]: Failed password for root from 192.0.2.10 port 22 ssh2\n"
        "Oct 19 09:00:01 host sshd[10]: message repeated 3 times: "
        "[ Failed password for root from 192.0.2.10 port 22 ssh2 ]\n"
        "Oct 19 09:00:02 host sshd[11]: Accepted publickey for root "
        "from 203.0.113.9 port 22 ssh2\n"
        "Oct 19 09:00:03 host sshd[12]: Invalid user root from 198.51.100.9\n"
        "Oct 19 09:00:04 host sshd[13]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.11 user=root\n",
        encoding="utf-8",
    )

    result = verify_counts(log, year=2026)

    assert result["raw_root_occurrences"] == 5
    assert result["parser_root_occurrences"] == 5
    assert result["matches"] is True
    assert result["repeated_message_records"] == 1
    assert result["represented_repeated_occurrences"] == 3
    assert result["repeat_count_if_includes_original"] == 2
    assert result["raw_record_types"] == {
        "ssh_password_failure": 4,
        "ssh_publickey_success": 1,
    }
    assert any(
        row["outcome"] == "success"
        and row["authentication_method"] == "publickey"
        and row["raw_count"] == 1
        for row in result["categories"]
    )


def test_independent_password_counts_distinguish_lines_repeats_and_context(tmp_path):
    log = tmp_path / "independent-counts.log"
    log.write_text(
        "Oct 19 09:00:00 host sshd[10]: Failed password for analyst "
        "from 192.0.2.10 port 22 ssh2\n"
        "Oct 19 09:00:01 host sshd[10]: message repeated 4 times: "
        "[ Failed password for analyst from 192.0.2.10 port 22 ssh2 ]\n"
        "Oct 19 09:00:02 host sshd[10]: Invalid user probe from 192.0.2.10\n"
        "Oct 19 09:00:03 host sshd[10]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=client.example user=probe\n"
        "Oct 19 09:00:04 host sshd[10]: input_userauth_request: invalid user probe [preauth]\n",
        encoding="utf-8",
    )

    result = verify_counts(log, year=2026)

    assert result["physical_input_lines"] == 5
    assert result["literal_failed_password_records"] == 1
    assert result["repeated_message_records"] == 1
    assert result["represented_repeated_occurrences"] == 4
    assert result["independent_password_failure_occurrences"] == 5
    assert result["per_source_password_failure_occurrences"] == {"192.0.2.10": 5}
    assert result["records_without_direct_source_ip"] == 2
    assert result["records_requiring_contextual_correlation"] == 3
    assert result["unresolved_or_ambiguous_records"] == 3
    assert result["per_source_password_failure_waves"]["192.0.2.10"] == [
        {
            "first_seen": "2026-10-19 09:00:00",
            "last_seen": "2026-10-19 09:00:01",
            "attempt_count": 5,
            "physical_failure_records": 2,
        }
    ]


def test_optional_loghub_reference_failure_counts_are_independently_verified():
    from pathlib import Path

    sample = Path(__file__).resolve().parents[1] / "sample_logs" / "OpenSSH_2k.log"
    if not sample.is_file():
        import pytest

        pytest.skip("optional OpenSSH_2k.log is not present; reference counts cannot be verified")

    result = verify_counts(sample, year=2016)
    expected = {
        "183.62.140.253": 286,
        "187.141.143.180": 80,
        "112.95.230.3": 26,
        "104.192.3.34": 2,
        "195.154.37.122": 2,
    }
    actual = result["per_source_password_failure_occurrences"]
    for source_ip, expected_count in expected.items():
        assert actual.get(source_ip, 0) == expected_count
    assert result["literal_failed_password_records"] == 518
    assert result["independent_password_failure_occurrences"] == 528
    assert result["first_wave_103_99_0_122_around_0911"] == 30


def test_independent_raw_wave_counter_preserves_separate_waves(tmp_path):
    log = tmp_path / "two-waves.log"
    first = [f"Oct 19 09:00:{second:02d}" for second in (0, 10, 20, 30, 40)]
    second = [f"Oct 19 09:02:{second:02d}" for second in (0, 10, 20, 30, 40)]
    rows = [
        f"{stamp} host sshd[{index}]: Failed password for analyst from 192.0.2.10 port 22 ssh2"
        for index, stamp in enumerate(first + second, start=1)
    ]
    log.write_text("\n".join(rows) + "\n", encoding="utf-8")

    result = verify_counts(log, year=2026)

    waves = result["per_source_password_failure_waves"]["192.0.2.10"]
    assert [wave["attempt_count"] for wave in waves] == [5, 5]
    assert waves[0]["last_seen"] == "2026-10-19 09:00:40"
    assert waves[1]["first_seen"] == "2026-10-19 09:02:00"
