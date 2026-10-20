"""
SSH Brute-Force Log Analyzer
============================

Main application that connects the log parser and detection engine.

Features:
- SSH authentication log analysis
- Five security detection rules
- Severity summary
- CSV and JSON report generation
- Command-line arguments
"""

import argparse
import csv
import json
import sys
import time as time_module
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

from config import load_allowlist, load_config
from detections import analyze_events
from event_accounting import effective_event_occurrences
from investigation import build_successful_login_rows
from ssh_parser import parse_log_file, parse_log_line
from web_parser import parse_web_log_file, parse_web_log_line

# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_LOG = Path("sample_logs/auth.log")
DEFAULT_REPORT_DIR = Path("reports")
VERSION = "0.4.0"
SCHEMA_VERSION = 7
SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


# ============================================================
# REPORT GENERATION
# ============================================================


def timestamp_interpretation(log_type: str, year: int) -> dict[str, object]:
    """Describe the year and timezone semantics used for parsed timestamps."""
    if log_type == "ssh":
        return {
            "year_for_yearless_timestamps": year,
            "timezone_assumption": (
                "timezone-unspecified for SSH syslog timestamps without an explicit offset; "
                "no host timezone is inferred."
            ),
            "offset_timestamp_policy": (
                "ISO timestamps with explicit offsets are normalized to UTC; "
                "timezone-naive timestamps remain timezone-naive."
            ),
        }
    if log_type == "web":
        return {
            "year_for_yearless_timestamps": None,
            "timezone_assumption": (
                "Nginx/Apache combined timestamps include an explicit numeric offset."
            ),
            "offset_timestamp_policy": "Explicit offsets are normalized to UTC.",
        }
    raise ValueError(f"Unsupported log type: {log_type}")


def _output_value(value):
    """Convert internal datetime values to ISO strings for report formats."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _output_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_output_value(item) for item in value]
    return value


def export_json(data, output_path):
    """Export alerts, incidents, risk scores, and parse stats as JSON."""

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(_output_value(data), file, indent=4)

    return output_path


def _safe_csv_cell(value):
    """Prefix spreadsheet formula-like log text so CSV opens as plain text."""
    if isinstance(value, str) and value.lstrip("\ufeff \t\r\n")[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    if isinstance(value, list):
        return [_safe_csv_cell(item) for item in value]
    if isinstance(value, dict):
        return {key: _safe_csv_cell(item) for key, item in value.items()}
    return value


def render_csv(alerts, timestamp_interpretation=None):
    """Serialize alerts to CSV using the same safe fields as file exports."""
    import io

    if not alerts:
        fieldnames = [
            "rule",
            "severity",
            "base_severity",
            "source_ip",
            "first_seen",
            "last_seen",
            "attempt_count",
            "usernames_targeted",
            "description",
            "mitre_attack_id",
            "mitre_technique_name",
            "recommended_action",
            "source_risk_score",
            "source_risk_band",
            "risk_score",
            "risk_band",
        ]
    else:
        fieldnames = list(dict.fromkeys(key for alert in alerts for key in alert.keys()))
    rows = [dict(alert) for alert in alerts]
    if timestamp_interpretation is not None:
        if "timestamp_interpretation" not in fieldnames:
            fieldnames.append("timestamp_interpretation")
        metadata = json.dumps(timestamp_interpretation, sort_keys=True)
        for row in rows:
            row["timestamp_interpretation"] = metadata
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(_safe_csv_cell(_output_value(alert)) for alert in rows)
    return output.getvalue()


def export_csv(alerts, output_path, *, timestamp_interpretation=None):
    """Export security alerts to a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_csv(alerts, timestamp_interpretation), encoding="utf-8", newline=""
    )
    return output_path


SUCCESSFUL_LOGIN_CSV_FIELDS = (
    "timestamp",
    "source_ip",
    "username",
    "hostname",
    "process_id",
    "session_identifier",
    "duration_seconds",
    "related_failures",
    "related_alert_rules",
    "correlation_status",
    "data_quality_limitations",
    "occurrence_count",
)


def render_successful_logins_csv(successful_logins):
    """Serialize successful-login evidence separately from alert rows."""
    import io

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=SUCCESSFUL_LOGIN_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(_safe_csv_cell(_output_value(row)) for row in successful_logins)
    return output.getvalue()


def export_successful_logins_csv(successful_logins, output_path):
    """Write the successful-login inventory to its own CSV artifact."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_successful_logins_csv(successful_logins), encoding="utf-8", newline=""
    )
    return output_path


# ============================================================
# ALERT SUMMARY
# ============================================================


def print_summary(events, result, parse_stats):
    """Display event counts and alert statistics."""

    alerts = result["alerts"]
    incidents = result["incidents"]
    risk_scores = result["risk_scores"]

    severity_counts = Counter(alert.get("base_severity", alert["severity"]) for alert in alerts)

    rule_counts = Counter(alert["rule"] for alert in alerts)

    print("\n" + "=" * 72)
    print("          SECURITY LOG ANALYZER")
    print("=" * 72)

    print(f"Log events analyzed            : {len(events)}")
    effective_count = parse_stats.get(
        "effective_event_occurrences", effective_event_occurrences(events)
    )
    print(f"Effective event occurrences    : {effective_count}")
    if "authentication_failures" in parse_stats:
        print(
            "Effective authentication attempts: "
            f"{parse_stats.get('effective_authentication_attempts', 0)}"
        )
        print(f"Authentication failures (all)   : {parse_stats['authentication_failures']}")
        print(
            "Password failures              : "
            f"{parse_stats.get('password_authentication_failures', 0)}"
        )
        print(
            f"Authentication-method probes   : {parse_stats.get('authentication_method_probes', 0)}"
        )
        print(f"Authentication successes       : {parse_stats['authentication_successes']}")
        print(f"Root failures (all methods)     : {parse_stats['root_authentication_failures']}")
        print(
            "Root password failures         : "
            f"{parse_stats.get('root_password_authentication_failures', 0)}"
        )
        print(f"Root authentication successes   : {parse_stats['root_authentication_successes']}")
        print(
            "Authentication context records : "
            f"{parse_stats.get('authentication_context_records', 0)}"
        )
        context_categories = parse_stats.get("authentication_context_categories", {})
        record_categories = parse_stats.get("parsed_record_categories", {})
        print(
            "Invalid-user / PAM / sshd-request context: "
            f"{context_categories.get('invalid_user', 0)} / "
            f"{context_categories.get('pam_authentication_failure', 0)} / "
            f"{context_categories.get('input_userauth_request', 0)}"
        )
        print(
            "Connection / identification records: "
            f"{record_categories.get('connection_closed', 0)} / "
            f"{record_categories.get('identification_missing', 0)}"
        )
        print(
            f"Context records linked         : {parse_stats.get('supporting_evidence_records', 0)}"
        )
        print(
            "Unattributed context records   : "
            f"{parse_stats.get('unattributed_contextual_records', 0)}"
        )
        print(
            "Unresolved/ambiguous context   : "
            f"{parse_stats.get('unresolved_or_ambiguous_context_records', 0)}"
        )
    print(f"Security alerts generated      : {len(alerts)}")
    print(
        "Parser coverage                : "
        f"{parse_stats['events_parsed']} events parsed, "
        f"{parse_stats['lines_ignored']} lines ignored, "
        f"{parse_stats['lines_malformed']} malformed"
    )
    print(f"Alerts suppressed by allowlist : {result['alerts_suppressed']}")

    print("\nALERT BASE SEVERITY SUMMARY")
    print("-" * 40)

    for severity in ("Critical", "High", "Medium", "Low"):
        print(f"{severity:<12}: {severity_counts.get(severity, 0)}")

    print("\nDETECTION SUMMARY")
    print("-" * 60)

    if not rule_counts:
        print("No suspicious activity detected.")
    else:
        for rule, count in sorted(rule_counts.items()):
            print(f"{rule:<35} {count}")

    print("\nINCIDENTS")
    print("-" * 72)
    if not incidents:
        print("No correlated incidents.")
    else:
        for incident in incidents:
            print(
                f"\n{incident['incident_id']} | {incident['combined_severity']} | {incident['source_ip']}"
            )
            print(f"    Rules      : {', '.join(incident['contributing_rules'])}")
            print(f"    First seen : {incident['first_seen'].isoformat()}")
            print(f"    Last seen  : {incident['last_seen'].isoformat()}")
            if incident.get("risk_score") is not None:
                print(f"    Source risk: {incident['risk_score']}/100 {incident['risk_band']}")
            print(f"    Summary    : {incident['summary']}")
            for session in incident.get("session_activity", []):
                print(
                    "    SSH session context: "
                    f"{session['event_type']} for {session['username']} on "
                    f"{session['hostname']} (sshd PID {session['process_id']}) "
                    f"at {session['timestamp']}"
                )

    print("\nALERT DETAILS")
    print("-" * 72)

    if not alerts:
        print("No alerts to display.")
    else:
        for index, alert in enumerate(alerts, start=1):
            print(f"\n[{index}] {alert['rule']}")
            print(f"    Base severity: {alert.get('base_severity', alert['severity'])}")
            print(f"    Source IP  : {alert['source_ip']}")
            print(f"    Window     : {alert['first_seen']} -> {alert['last_seen']}")
            print(f"    Attempts   : {alert['attempt_count']}")
            if alert.get("risk_score") is not None:
                print(
                    f"    Source risk (composite): {alert['source_risk_score']}/100 {alert['source_risk_band']}"
                )
            print(f"    Usernames  : {', '.join(alert['usernames_targeted']) or '(none)'}")
            print(f"    Description: {alert['description']}")
            for session in alert.get("session_activity", []):
                print(
                    "    SSH session: "
                    f"opened for {session['username']} on {session['hostname']} "
                    f"(sshd PID {session['process_id']}) at {session['timestamp']}"
                )
            print(f"    ATT&CK     : {alert['mitre_attack_id']} - {alert['mitre_technique_name']}")
            print(f"    Action     : {alert['recommended_action']}")

    print("\nTOP RISKY IPS")
    print("-" * 40)
    print(f"{'Source IP':<20} Risk score / band")
    for ip, risk in list(risk_scores.items())[:10]:
        print(f"{ip:<20} {risk['score']:>3}/100 {risk['band']}")

    print("\n" + "=" * 72)


# ============================================================
# MAIN ANALYSIS
# ============================================================


def load_input(
    path: str | Path,
    log_type: str,
    year: int,
    *,
    include_malformed_records: bool = False,
):
    """Validate the input path and parse it using its selected log format."""
    log_path = Path(path)
    if not log_path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")
    if log_type == "ssh":
        return parse_log_file(
            log_path, year=year, include_malformed_records=include_malformed_records
        )
    if log_type == "web":
        return parse_web_log_file(log_path, include_malformed_records=include_malformed_records)
    raise ValueError(f"Unsupported log type: {log_type}")


def print_malformed_summary(parse_stats: dict, *, output=print, sample_limit: int = 50) -> None:
    """Print grouped malformed counts and bounded line-number-only samples."""
    reasons = parse_stats.get("malformed_by_reason", {})
    records = parse_stats.get("malformed_records", [])
    output("\nMALFORMED INPUT SUMMARY")
    if not reasons:
        output("No malformed records.")
        return
    for reason, count in sorted(reasons.items()):
        output(f"{reason}: {count}")
    for record in records[:sample_limit]:
        output(f"  line {record['line_number']}: {record['reason']}")
    omitted = max(0, len(records) - sample_limit) + parse_stats.get(
        "malformed_records_truncated", 0
    )
    if omitted:
        output(f"  {omitted} additional malformed record locations omitted")


def _filter_result(result, min_severity):
    """Filter alerts and incidents to the requested minimum severity."""
    if min_severity is None:
        return result
    minimum = SEVERITY_ORDER[min_severity]
    filtered = dict(result)
    filtered["alerts"] = [a for a in result["alerts"] if SEVERITY_ORDER[a["severity"]] >= minimum]
    filtered["incidents"] = [
        i for i in result["incidents"] if SEVERITY_ORDER[i["combined_severity"]] >= minimum
    ]
    return filtered


class CliArgumentParser(argparse.ArgumentParser):
    """Argument parser that lets :func:`main` return the documented error code."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        raise ValueError(message)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser and document configuration precedence."""
    parser = CliArgumentParser(
        description="Analyze authorized SSH or web-server logs offline.",
        epilog="For thresholds, CLI flags override config.yaml, which overrides built-in defaults.",
    )
    parser.add_argument("--file", default=str(DEFAULT_LOG), help="Input log file.")
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        help="Year assigned to yearless SSH syslog timestamps.",
    )
    parser.add_argument("--config", default="config.yaml", help="YAML configuration file.")
    parser.add_argument("--allowlist", help="Optional trusted IP/CIDR file.")
    parser.add_argument(
        "--output-dir", default=str(DEFAULT_REPORT_DIR), help="Report output directory."
    )
    parser.add_argument(
        "--format",
        choices=("console", "csv", "json", "html", "all"),
        default="all",
        help="Output format (default: all).",
    )
    parser.add_argument(
        "--min-severity",
        choices=("Low", "Medium", "High"),
        help="Only include alerts and incidents at or above this severity.",
    )
    parser.add_argument(
        "--brute-threshold", type=int, help="Override the SSH brute-force threshold."
    )
    parser.add_argument(
        "--window", type=int, help="Override the SSH brute-force window in seconds."
    )
    parser.add_argument(
        "--log-type", choices=("ssh", "web"), default="ssh", help="Input log format."
    )
    parser.add_argument(
        "--follow", action="store_true", help="Watch appended log lines for new alerts."
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress console report output.")
    parser.add_argument(
        "--show-malformed",
        action="store_true",
        help="Show grouped malformed-line reasons and up to 50 line numbers (no raw log text).",
    )
    parser.add_argument("--version", action="version", version=f"sshlog-analyzer {VERSION}")
    return parser


def _exit_code(result) -> int:
    """Return the documented automation code for the filtered detections."""
    high_or_critical = {"High", "Critical"}
    if any(alert["severity"] in high_or_critical for alert in result["alerts"]):
        return 2
    if any(incident["combined_severity"] in high_or_critical for incident in result["incidents"]):
        return 2
    return 1 if result["alerts"] else 0


def _stable_alert_key(alert: dict) -> tuple:
    """Identify an aggregate by its rule and fixed window's first timestamp."""
    return (
        alert.get("rule"),
        alert.get("source_ip"),
        str(alert.get("first_seen")),
        alert.get("target_username"),
        tuple(alert.get("source_ips", [])),
    )


def follow_log(
    path: str | Path,
    *,
    config: dict,
    allowlist,
    year: int,
    output=print,
    stop_event: Event | None = None,
    poll_interval: float = 1.0,
    max_events: int = 10_000,
    max_polls: int | None = None,
    min_severity: str | None = None,
    log_type: str = "ssh",
) -> None:
    """Tail appended SSH lines, re-evaluating a bounded event window.

    The file is read-only. The current file position starts at EOF, while
    rotation and truncation reset the position. A set of stable alert keys
    prevents an aggregate from being emitted repeatedly as its count grows.
    ``max_polls`` and ``stop_event`` support deterministic tests and shutdown.
    """
    log_path = Path(path)
    if poll_interval < 0:
        raise ValueError("poll_interval cannot be negative")
    recent_events = deque(maxlen=max_events)
    if max_events < 1:
        raise ValueError("max_events must be positive")
    seen_alerts: dict[tuple, int] = {}
    initial_stat = log_path.stat() if log_path.is_file() else None
    file_id = (initial_stat.st_dev, initial_stat.st_ino) if initial_stat else None
    offset = initial_stat.st_size if initial_stat else 0
    partial = ""
    polls = 0
    line_identity = 0
    waiting_reported = False
    while stop_event is None or not stop_event.is_set():
        try:
            current_stat = log_path.stat()
        except FileNotFoundError:
            current_stat = None
        if current_stat is None:
            if file_id is not None:
                file_id = None
                offset = 0
                partial = ""
                recent_events.clear()
            if not waiting_reported and output is not None:
                output(f"Waiting for log file: {log_path}")
            waiting_reported = True
        else:
            current_id = (current_stat.st_dev, current_stat.st_ino)
            if file_id is None:
                file_id = current_id
                offset = 0
                partial = ""
            elif current_id != file_id or current_stat.st_size < offset:
                file_id = current_id
                offset = 0
                partial = ""
                recent_events.clear()
            waiting_reported = False
            if current_stat.st_size > offset:
                with log_path.open("rb") as log_file:
                    log_file.seek(offset)
                    chunk = log_file.read()
                    offset = log_file.tell()
                combined = partial + chunk.decode("utf-8", errors="replace")
                pieces = combined.splitlines(keepends=True)
                complete_lines = []
                partial = ""
                if pieces and not pieces[-1].endswith(("\n", "\r")):
                    partial = pieces.pop()
                complete_lines.extend(pieces)
                for line in complete_lines:
                    event = (
                        parse_log_line(line, year=year)
                        if log_type == "ssh"
                        else parse_web_log_line(line)
                    )
                    is_supported_event = event is not None and (
                        event.get("event_type", "").startswith("authentication_")
                        or event.get("event_type") == "web_request"
                    )
                    if is_supported_event:
                        line_identity += 1
                        event["_event_id"] = f"follow:{file_id[0]}:{file_id[1]}:{line_identity}"
                        recent_events.append(event)
                if recent_events:
                    result = analyze_events(
                        list(recent_events),
                        config=config,
                        allowlist=allowlist,
                        log_type=log_type,
                    )
                    result = _filter_result(result, min_severity)
                    for alert in result["alerts"]:
                        key = _stable_alert_key(alert)
                        count = int(alert.get("attempt_count", 0))
                        previous_count = seen_alerts.get(key)
                        if previous_count is not None and count - previous_count < 5:
                            continue
                        seen_alerts[key] = count
                        if output is not None:
                            update = "" if previous_count is None else " (attempt count increased)"
                            output(
                                f"NEW ALERT {alert['rule']} | {alert['severity']} | "
                                f"{alert['source_ip']} | attempts={alert['attempt_count']}{update}"
                            )
        polls += 1
        if max_polls is not None and polls >= max_polls:
            break
        if stop_event is not None and stop_event.wait(poll_interval):
            break
        if stop_event is None:
            time_module.sleep(poll_interval)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI with optional argument list and return its automation code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        config = load_config(args.config)
        if args.brute_threshold is not None:
            if args.brute_threshold < 1:
                raise ValueError("--brute-threshold must be a positive integer")
            config["brute_force"]["threshold"] = args.brute_threshold
        if args.window is not None:
            if args.window < 1:
                raise ValueError("--window must be a positive integer")
            config["brute_force"]["window_seconds"] = args.window
        allowlist = load_allowlist(args.allowlist)
        if args.follow:
            follow_log(
                args.file,
                config=config,
                allowlist=allowlist,
                year=args.year,
                output=None if args.quiet else print,
                min_severity=args.min_severity,
                log_type=args.log_type,
            )
            return 0
        events, parse_stats = load_input(
            args.file,
            args.log_type,
            args.year,
            include_malformed_records=args.show_malformed,
        )
        result = analyze_events(events, config=config, allowlist=allowlist, log_type=args.log_type)
        result = _filter_result(result, args.min_severity)
        result["config_used"] = config
        result["parse_stats"] = parse_stats
        result["version"] = VERSION
        result["schema_version"] = SCHEMA_VERSION
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        result["timestamp_interpretation"] = timestamp_interpretation(args.log_type, args.year)
        result["successful_logins"] = (
            build_successful_login_rows(
                events,
                result["alerts"],
                lookback_seconds=config["success_after_failures"]["lookback_seconds"],
            )
            if args.log_type == "ssh"
            else []
        )

        output_dir = Path(args.output_dir)
        if args.format in ("csv", "all"):
            export_csv(
                result["alerts"],
                output_dir / "alerts.csv",
                timestamp_interpretation=result["timestamp_interpretation"],
            )
            export_successful_logins_csv(
                result["successful_logins"], output_dir / "successful_logins.csv"
            )
        if args.format in ("json", "all"):
            export_json(result, output_dir / "alerts.json")
        if args.format in ("html", "all"):
            from html_report import export_html_report

            export_html_report(events, result, output_dir / "report.html")
        if args.format in ("console", "all") and not args.quiet:
            print_summary(events, result, parse_stats)
            print(f"\nReports directory: {output_dir}")
        if args.show_malformed and not args.quiet:
            print_malformed_summary(parse_stats)
        return _exit_code(result)
    except SystemExit as error:
        return int(error.code or 0)
    except KeyboardInterrupt:
        return 0
    except (FileNotFoundError, PermissionError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
