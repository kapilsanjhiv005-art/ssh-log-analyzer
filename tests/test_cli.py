"""CLI parsing, configuration precedence, filtering, and exit-code tests."""

import csv
import json
import threading
import time

import analyzer
from config import load_config


def write_events(path, count=5, start=0, ip="198.51.100.25"):
    """Write deterministic documentation-IP SSH failures for CLI tests."""
    rows = []
    for index in range(count):
        second = start + index
        rows.append(
            f"Oct 19 09:00:{second:02d} test sshd[{1000 + index}]: Failed password for analyst "
            f"from {ip} port 44000 ssh2"
        )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_parser_exposes_requested_options_and_precedence_help(capsys):
    args = analyzer.build_parser().parse_args(
        [
            "--file",
            "input.log",
            "--year",
            "2025",
            "--config",
            "custom.yaml",
            "--allowlist",
            "trusted.txt",
            "--output-dir",
            "out",
            "--format",
            "json",
            "--min-severity",
            "High",
            "--brute-threshold",
            "9",
            "--window",
            "30",
            "--log-type",
            "ssh",
            "--follow",
            "--quiet",
        ]
    )
    assert args.brute_threshold == 9
    assert args.follow and args.quiet
    help_text = analyzer.build_parser().format_help()
    assert "CLI flags override config.yaml" in help_text
    assert "--show-malformed" in help_text
    assert analyzer.main(["--version"]) == 0
    assert "sshlog-analyzer" in capsys.readouterr().out


def test_cli_flags_override_config_file_thresholds(tmp_path):
    log = tmp_path / "auth.log"
    write_events(log, count=3)
    config = tmp_path / "config.yaml"
    config.write_text("brute_force:\n  threshold: 2\n  window_seconds: 60\n", encoding="utf-8")
    output = tmp_path / "out"

    code = analyzer.main(
        [
            "--file",
            str(log),
            "--config",
            str(config),
            "--brute-threshold",
            "4",
            "--format",
            "json",
            "--output-dir",
            str(output),
        ]
    )

    assert code == 0
    report = json.loads((output / "alerts.json").read_text(encoding="utf-8"))
    assert report["config_used"]["brute_force"]["threshold"] == 4
    assert report["version"] == analyzer.VERSION
    assert report["schema_version"] == analyzer.SCHEMA_VERSION
    assert report["generated_at"]
    assert all("risk_band" in alert and "risk_score" in alert for alert in report["alerts"])


def test_empty_output_formats_write_valid_reports(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    output = tmp_path / "empty-reports"
    assert (
        analyzer.main(
            [
                "--file",
                str(log),
                "--format",
                "all",
                "--output-dir",
                str(output),
                "--quiet",
            ]
        )
        == 0
    )
    assert json.loads((output / "alerts.json").read_text(encoding="utf-8"))["alerts"] == []
    assert (output / "alerts.csv").read_text(encoding="utf-8").startswith("rule,severity")
    html = (output / "report.html").read_text(encoding="utf-8")
    assert "No alerts were generated." in html
    assert "No source IPs." in html


def test_csv_prefixes_spreadsheet_formula_like_log_text(tmp_path):
    output = tmp_path / "alerts.csv"
    analyzer.export_csv(
        [
            {
                "rule": "ssh_test",
                "severity": "Low",
                "source_ip": "198.51.100.25",
                "description": '=HYPERLINK("https://example.invalid")',
                "usernames_targeted": ["+SUM(1,1)"],
            }
        ],
        output,
    )

    with output.open(newline="", encoding="utf-8") as report:
        row = next(csv.DictReader(report))
    assert row["description"].startswith("'=HYPERLINK")
    assert "'+SUM" in row["usernames_targeted"]


def test_cli_exit_codes_zero_one_two_and_three(tmp_path, capsys):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    assert analyzer.main(["--file", str(empty), "--format", "console", "--quiet"]) == 0

    medium = tmp_path / "medium.log"
    write_events(medium, count=5)
    assert analyzer.main(["--file", str(medium), "--format", "console", "--quiet"]) == 1

    assert (
        analyzer.main(
            ["--file", "sample_logs/auth.log", "--year", "2026", "--format", "console", "--quiet"]
        )
        == 2
    )

    assert analyzer.main(["--file", str(tmp_path / "missing.log")]) == 3
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("brute_force:\n  threshold: -4\n", encoding="utf-8")
    assert analyzer.main(["--file", str(empty), "--config", str(bad_config)]) == 3
    errors = capsys.readouterr().err
    assert "Log file not found" in errors
    assert "positive integer" in errors


def test_console_summary_reports_ssh_risk_incidents_and_parse_coverage(capsys):
    code = analyzer.main(
        [
            "--file",
            "sample_logs/auth.log",
            "--year",
            "2026",
            "--format",
            "console",
        ]
    )

    output = capsys.readouterr().out
    assert code == 2
    assert "Log events analyzed            : 37" in output
    assert (
        "Parser coverage                : 37 events parsed, 0 lines ignored, 0 malformed" in output
    )
    assert "INC-002 | Critical | 198.51.100.60" in output
    assert "Source risk: 75/100 Critical" in output
    assert "Base severity: High" in output


def test_web_console_summary_reports_alerts_and_no_incidents(capsys):
    code = analyzer.main(
        [
            "--file",
            "sample_logs/web_access.log",
            "--log-type",
            "web",
            "--format",
            "console",
        ]
    )

    output = capsys.readouterr().out
    assert code == 1
    assert "Log events analyzed            : 23" in output
    assert "web_login_bruteforce" in output
    assert "No correlated incidents." in output


def test_min_severity_filters_alert_json_and_exit_code(tmp_path):
    output = tmp_path / "high-only"
    code = analyzer.main(
        [
            "--file",
            "sample_logs/auth.log",
            "--year",
            "2026",
            "--format",
            "json",
            "--min-severity",
            "High",
            "--output-dir",
            str(output),
        ]
    )
    assert code == 2
    report = json.loads((output / "alerts.json").read_text(encoding="utf-8"))
    assert report["alerts"]
    assert all(alert["severity"] == "High" for alert in report["alerts"])
    assert report["incidents"]
    assert all(incident["combined_severity"] == "Critical" for incident in report["incidents"])


def test_critical_composite_incident_uses_high_exit_code():
    result = {
        "alerts": [{"severity": "Low"}],
        "incidents": [{"combined_severity": "Critical"}],
    }
    assert analyzer._exit_code(result) == 2


def test_bad_cli_values_return_error_without_traceback(tmp_path, capsys):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    assert analyzer.main(["--file", str(log), "--brute-threshold", "0"]) == 3
    assert "Traceback" not in capsys.readouterr().err


def test_show_malformed_prints_grouped_reasons_and_bounded_locations(tmp_path, capsys):
    log = tmp_path / "malformed.log"
    log.write_text(
        "Oct 19 09:00:00 test sshd[1]: Failed password for root from nowhere\n"
        "unknown local service record\n",
        encoding="utf-8",
    )

    code = analyzer.main(
        [
            "--file",
            str(log),
            "--format",
            "console",
            "--show-malformed",
            "--output-dir",
            str(tmp_path),
        ]
    )

    output = capsys.readouterr().out
    assert code == 0
    assert "invalid_source_ip: 1" in output
    assert "line 1: invalid_source_ip" in output
    assert "Failed password" not in output


def test_show_malformed_supports_web_input(tmp_path, capsys):
    log = tmp_path / "malformed-access.log"
    log.write_text("not a combined access record\n", encoding="utf-8")

    code = analyzer.main(
        [
            "--file",
            str(log),
            "--log-type",
            "web",
            "--format",
            "console",
            "--show-malformed",
            "--output-dir",
            str(tmp_path),
        ]
    )

    output = capsys.readouterr().out
    assert code == 0
    assert "unsupported_or_truncated_format: 1" in output
    assert "line 1: unsupported_or_truncated_format" in output


def test_follow_emits_each_aggregate_only_once(tmp_path):
    log = tmp_path / "follow.log"
    log.write_text("", encoding="utf-8")
    stop = threading.Event()
    emitted = threading.Event()
    messages = []

    def collect(message):
        messages.append(message)
        emitted.set()

    worker = threading.Thread(
        target=analyzer.follow_log,
        kwargs={
            "path": log,
            "config": load_config(None),
            "allowlist": None,
            "year": 2026,
            "output": collect,
            "stop_event": stop,
            "poll_interval": 0.01,
            "max_polls": 300,
        },
        daemon=True,
    )
    worker.start()
    time.sleep(0.04)
    write_events(log, count=5)
    assert emitted.wait(2)
    time.sleep(0.05)
    stop.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(messages) == 1
    assert messages[0].startswith("NEW ALERT ssh_brute_force")


def test_follow_waits_cleanly_for_missing_file(tmp_path):
    messages = []
    analyzer.follow_log(
        tmp_path / "absent.log",
        config=load_config(None),
        allowlist=None,
        year=2026,
        max_polls=1,
        poll_interval=0,
        output=messages.append,
    )
    assert messages == [f"Waiting for log file: {tmp_path / 'absent.log'}"]


def test_follow_emits_meaningful_attempt_count_update(tmp_path):
    log = tmp_path / "follow-update.log"
    log.write_text("", encoding="utf-8")
    messages = []
    stop = threading.Event()
    worker = threading.Thread(
        target=analyzer.follow_log,
        kwargs={
            "path": log,
            "config": load_config(None),
            "allowlist": None,
            "year": 2026,
            "output": messages.append,
            "stop_event": stop,
            "poll_interval": 0.01,
            "max_polls": 300,
        },
        daemon=True,
    )
    worker.start()
    time.sleep(0.04)
    write_events(log, count=5)
    deadline = time.monotonic() + 2
    while len(messages) < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    with log.open("a", encoding="utf-8") as output:
        for index in range(5, 10):
            output.write(
                f"Oct 19 09:00:{index:02d} test sshd[{1000 + index}]: "
                "Failed password for analyst from 198.51.100.25 port 44000 ssh2\n"
            )
    deadline = time.monotonic() + 2
    while len(messages) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert len(messages) == 2
    assert "attempts=5" in messages[0]
    assert "attempts=10" in messages[1]


def test_follow_truncation_starts_a_fresh_bounded_window(tmp_path):
    log = tmp_path / "follow-truncate.log"
    log.write_text("", encoding="utf-8")
    messages = []
    stop = threading.Event()
    worker = threading.Thread(
        target=analyzer.follow_log,
        kwargs={
            "path": log,
            "config": load_config(None),
            "allowlist": None,
            "year": 2026,
            "output": messages.append,
            "stop_event": stop,
            "poll_interval": 0.01,
            "max_polls": 400,
        },
        daemon=True,
    )
    worker.start()
    time.sleep(0.04)
    write_events(log, count=5)
    deadline = time.monotonic() + 2
    while len(messages) < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    log.write_text("", encoding="utf-8")
    time.sleep(0.05)
    write_events(log, count=5, start=20)
    deadline = time.monotonic() + 2
    while len(messages) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert len(messages) == 2
    assert "attempts=5" in messages[1]


def test_json_report_discloses_timestamp_timezone_assumptions(tmp_path):
    log = tmp_path / "yearless.log"
    log.write_text(
        "Oct 19 09:00:00 host sshd[1]: Failed password for analyst from 192.0.2.10 port 22 ssh2\n",
        encoding="utf-8",
    )
    output = tmp_path / "reports"

    assert (
        analyzer.main(
            [
                "--file",
                str(log),
                "--year",
                "2016",
                "--format",
                "json",
                "--output-dir",
                str(output),
                "--quiet",
            ]
        )
        == 0
    )
    report = json.loads((output / "alerts.json").read_text(encoding="utf-8"))
    interpretation = report["timestamp_interpretation"]
    assert interpretation["year_for_yearless_timestamps"] == 2016
    assert "timezone-unspecified" in interpretation["timezone_assumption"]
    assert "normalized to UTC" in interpretation["offset_timestamp_policy"]


def test_csv_report_carries_shared_timestamp_interpretation_metadata():
    interpretation = analyzer.timestamp_interpretation("ssh", 2016)
    rows = csv.DictReader(
        analyzer.render_csv(
            [{"rule": "ssh_brute_force", "first_seen": "2016-10-19T09:00:00"}],
            interpretation,
        ).splitlines()
    )

    row = next(rows)
    assert json.loads(row["timestamp_interpretation"]) == interpretation


def test_cli_exports_successful_login_inventory_with_conservative_duration(tmp_path):
    log = tmp_path / "session.log"
    log.write_text(
        "Oct 19 09:00:00 edge sshd[412]: Accepted password for analyst from 192.0.2.70 port 22 ssh2\n"
        "Oct 19 09:00:01 edge sshd[412]: pam_unix(sshd:session): session opened for user analyst by (uid=0)\n"
        "Oct 19 09:12:46 edge sshd[412]: pam_unix(sshd:session): session closed for user analyst\n",
        encoding="utf-8",
    )
    output = tmp_path / "reports"

    code = analyzer.main(
        [
            "--file",
            str(log),
            "--year",
            "2016",
            "--format",
            "all",
            "--output-dir",
            str(output),
            "--quiet",
        ]
    )

    assert code == 0
    report = json.loads((output / "alerts.json").read_text(encoding="utf-8"))
    assert len(report["successful_logins"]) == 1
    assert report["successful_logins"][0]["duration_seconds"] == 766
    assert report["successful_logins"][0]["session_identifier"] is None
    assert "Successful logins" in (output / "report.html").read_text(encoding="utf-8")
    login_rows = list(csv.DictReader((output / "successful_logins.csv").open(encoding="utf-8")))
    assert login_rows[0]["duration_seconds"] == "766"
