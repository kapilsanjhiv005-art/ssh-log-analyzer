"""Independently count raw OpenSSH authentication outcomes and compare the parser.

This utility uses local regular expressions and bounded record summaries. It
does not invoke detection rules, expand repeat weights, upload, or modify logs.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ssh_parser import parse_log_file

HEADER = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}[T ]\S+))\s+(?P<host>\S+)\s+"
    r"sshd(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
REPEATED = re.compile(
    r"^message repeated (?P<count>\d+) times:\s*\[(?P<message>.*)\]$", re.IGNORECASE
)
AUTH = re.compile(
    r"^(?P<outcome>Accepted|Failed)\s+(?P<method>\S+)\s+for\s+"
    r"(?:(?:invalid user)\s+)?(?P<username>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
INVALID_USER = re.compile(
    r"^Invalid user\s+(?P<username>\S+)(?:\s+from\s+(?P<ip>\S+))?", re.IGNORECASE
)
PAM = re.compile(r"pam_unix\(sshd:auth\): authentication failure;", re.IGNORECASE)
PAM_USER = re.compile(r"(?:^|\s)user=(?P<username>\S+)")
PAM_RHOST = re.compile(r"(?:^|\s)rhost=(?P<host>\S+)")
INPUT_USERAUTH = re.compile(r"^input_userauth_request:", re.IGNORECASE)
INPUT_USER = re.compile(r"(?:invalid user|for user)\s+(?P<username>\S+)", re.IGNORECASE)
MAX_REPEAT = 1_000_000
MAX_CONTEXT_GAP_SECONDS = 10


def _parse_time(value: str, year: int) -> datetime | None:
    """Parse supported timestamp styles without calling the production parser."""
    try:
        if re.match(r"^[A-Z][a-z]{2}\s", value):
            return datetime.strptime(f"{year} {value}", "%Y %b %d %H:%M:%S")
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo:
        return timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    return timestamp


def _valid_ip(value: str | None) -> str | None:
    """Return a normalized IP string or None for non-IP source labels."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def _safe_pid(value: str | None) -> int | None:
    """Parse a bounded PID token without allowing oversized integer conversion."""
    if value is None or len(value) > 18:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _raw_review(path: Path, year: int) -> dict[str, Any]:
    """Count terminal outcomes and lightweight context from raw lines."""
    lines = 0
    literal_password_records = 0
    repeated_records = 0
    repeated_weight = 0
    repeated_alternative = 0
    password_failures: Counter[str] = Counter()
    password_records_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    roots: Counter[tuple[str, str, str]] = Counter()
    outcome_types: Counter[str] = Counter()
    context_records: list[dict[str, Any]] = []
    terminal_records: list[dict[str, Any]] = []
    records_without_source = 0
    previous_month: int | None = None
    inferred_year = year

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            lines += 1
            header = HEADER.match(line.strip())
            if not header:
                continue
            timestamp_text = header.group("timestamp")
            if re.match(r"^[A-Z][a-z]{2}\s", timestamp_text):
                month = datetime.strptime(timestamp_text[:3], "%b").month
                if previous_month == 12 and month == 1:
                    inferred_year += 1
                previous_month = month
            timestamp = _parse_time(timestamp_text, inferred_year)
            if timestamp is None:
                continue
            message = header.group("message")
            weight = 1
            repeated = REPEATED.match(message)
            if repeated:
                text = repeated.group("count")
                if len(text) > 7:
                    continue
                weight = int(text)
                if not 1 <= weight <= MAX_REPEAT:
                    continue
                repeated_records += 1
                repeated_weight += weight
                repeated_alternative += max(weight - 1, 0)
                message = repeated.group("message").strip()

            outcome = AUTH.match(message)
            if outcome:
                outcome_name = outcome.group("outcome").casefold()
                normalized_outcome = "success" if outcome_name == "accepted" else "failure"
                method = outcome.group("method").casefold()
                username = outcome.group("username")
                source = _valid_ip(outcome.group("ip"))
                terminal = {
                    "line_number": line_number,
                    "timestamp": timestamp,
                    "hostname": header.group("host"),
                    "process_id": _safe_pid(header.group("pid")),
                    "username": username,
                    "source_ip": source,
                    "outcome": outcome_name,
                    "method": method,
                    "occurrence_count": weight,
                }
                terminal_records.append(terminal)
                outcome_types[f"ssh_{method}_{normalized_outcome}"] += weight
                if not source:
                    records_without_source += 1
                if outcome_name == "failed" and method == "password":
                    if not repeated:
                        literal_password_records += 1
                    source_key = source or "unattributed"
                    password_failures[source_key] += weight
                    password_records_by_source[source_key].append(
                        {"timestamp": timestamp, "weight": weight, "line_number": line_number}
                    )
                if username.casefold() == "root":
                    roots[(normalized_outcome, method, source or "unattributed")] += weight
                continue

            invalid = INVALID_USER.match(message)
            pam = PAM.search(message)
            input_request = INPUT_USERAUTH.match(message)
            if invalid or pam or input_request:
                if invalid:
                    username = invalid.group("username")
                    source_value = invalid.group("ip")
                elif pam:
                    username_match = PAM_USER.search(message)
                    rhost_match = PAM_RHOST.search(message)
                    username = username_match.group("username") if username_match else None
                    source_value = rhost_match.group("host") if rhost_match else None
                else:
                    username_match = INPUT_USER.search(message)
                    username = username_match.group("username") if username_match else None
                    source_value = None
                source = _valid_ip(source_value)
                if not source:
                    records_without_source += 1
                context_records.append(
                    {
                        "line_number": line_number,
                        "timestamp": timestamp,
                        "hostname": header.group("host"),
                        "process_id": _safe_pid(header.group("pid")),
                        "username": username,
                        "source_ip": source,
                    }
                )

    resolved = 0
    unresolved = 0
    for context in context_records:
        candidates = [
            event
            for event in terminal_records
            if context["hostname"] == event["hostname"]
            and context["process_id"] is not None
            and context["process_id"] == event["process_id"]
            and context["username"]
            and context["username"] == event["username"]
            and (
                not context["source_ip"]
                or not event["source_ip"]
                or context["source_ip"] == event["source_ip"]
            )
            and abs((context["timestamp"] - event["timestamp"]).total_seconds())
            <= MAX_CONTEXT_GAP_SECONDS
        ]
        if len(candidates) == 1:
            resolved += 1
        else:
            unresolved += 1

    per_source_waves: dict[str, list[dict[str, Any]]] = {}
    for source, records in sorted(password_records_by_source.items()):
        waves: list[list[dict[str, Any]]] = []
        for record in sorted(records, key=lambda item: item["timestamp"]):
            if not waves or (record["timestamp"] - waves[-1][-1]["timestamp"]).total_seconds() > 60:
                waves.append([record])
            else:
                waves[-1].append(record)
        per_source_waves[source] = [
            {
                "first_seen": wave[0]["timestamp"].isoformat(sep=" "),
                "last_seen": wave[-1]["timestamp"].isoformat(sep=" "),
                "attempt_count": sum(record["weight"] for record in wave),
                "physical_failure_records": len(wave),
            }
            for wave in waves
        ]
    first_103_wave = next(
        (
            wave["attempt_count"]
            for wave in per_source_waves.get("103.99.0.122", [])
            if wave["first_seen"].endswith("09:11:21")
        ),
        0,
    )

    return {
        "physical_input_lines": lines,
        "literal_failed_password_records": literal_password_records,
        "repeated_message_records": repeated_records,
        "represented_repeated_occurrences": repeated_weight,
        "repeat_count_if_includes_original": repeated_alternative,
        "independent_password_failure_occurrences": sum(password_failures.values()),
        "per_source_password_failure_occurrences": dict(sorted(password_failures.items())),
        "per_source_password_failure_waves": per_source_waves,
        "records_without_direct_source_ip": records_without_source,
        "records_requiring_contextual_correlation": len(context_records),
        "resolved_context_records": resolved,
        "unresolved_or_ambiguous_records": unresolved,
        "first_wave_103_99_0_122_around_0911": first_103_wave,
        "raw_root_occurrences": sum(roots.values()),
        "raw_record_types": dict(sorted(outcome_types.items())),
        "_root_counts": roots,
    }


def verify_counts(path: str | Path, year: int) -> dict[str, Any]:
    """Compare independent raw terminal outcomes with parser output and report counts."""
    log_path = Path(path)
    raw = _raw_review(log_path, year)
    parsed_events, parser_stats = parse_log_file(log_path, year=year)
    parsed_roots: Counter[tuple[str, str, str]] = Counter()
    parsed_password_failures: Counter[str] = Counter()
    for event in parsed_events:
        event_type = event.get("event_type")
        if event_type not in {"authentication_failure", "authentication_success"}:
            continue
        outcome = "success" if event_type == "authentication_success" else "failure"
        method = (event.get("authentication_method") or "unknown").casefold()
        source = event.get("source_ip") or "unattributed"
        username = (event.get("username") or "").casefold()
        weight = event.get("occurrence_count", 1)
        if not isinstance(weight, int) or weight < 1:
            weight = 1
        if username == "root":
            parsed_roots[(outcome, method, source)] += weight
        if outcome == "failure" and method == "password":
            parsed_password_failures[source] += weight

    raw_roots: Counter[tuple[str, str, str]] = raw.pop("_root_counts")
    root_keys = sorted(set(raw_roots) | set(parsed_roots))
    categories = [
        {
            "outcome": outcome,
            "authentication_method": method,
            "source_ip": source,
            "raw_count": raw_roots[(outcome, method, source)],
            "parser_count": parsed_roots[(outcome, method, source)],
            "difference": parsed_roots[(outcome, method, source)]
            - raw_roots[(outcome, method, source)],
        }
        for outcome, method, source in root_keys
    ]
    expected_root = dict(raw_roots)
    actual_root = dict(parsed_roots)
    raw_password = raw["per_source_password_failure_occurrences"]
    parser_password = dict(sorted(parsed_password_failures.items()))
    result = {
        **raw,
        "parser_lines_read": parser_stats["lines_read"],
        "parser_password_failure_occurrences": sum(parsed_password_failures.values()),
        "parser_per_source_password_failure_occurrences": parser_password,
        "password_failure_counts_match": raw_password == parser_password,
        "parser_root_occurrences": sum(parsed_roots.values()),
        "categories": categories,
        "root_counts_match": expected_root == actual_root,
        "matches": raw_password == parser_password and expected_root == actual_root,
        "counting_note": (
            "Authentication attempts count terminal Accepted/Failed outcome records by method; "
            "Invalid user, PAM, and input_userauth_request lines are contextual evidence, not "
            "additional attempts. Repeated summaries contribute their reported N weights."
        ),
        "time_window_note": (
            "The 103.99.0.122 value is the exact 09:11 minute bucket; verify source dataset "
            "timestamps before interpreting it as a wider wave."
        ),
    }
    return result


def main(argv: list[str] | None = None) -> int:
    """Print a machine-readable local comparison; return 0 when counts match."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Local OpenSSH log to inspect")
    parser.add_argument("--year", type=int, default=2026, help="Year for yearless syslog records")
    args = parser.parse_args(argv)
    if not args.file.is_file():
        parser.error(f"input file does not exist: {args.file}")
    result = verify_counts(args.file, args.year)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
