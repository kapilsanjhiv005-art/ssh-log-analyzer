"""Parse common OpenSSH authentication and connection log messages."""

from __future__ import annotations

import ipaddress
import logging
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from event_accounting import effective_event_occurrences, ssh_authentication_counts

logger = logging.getLogger(__name__)

SYSLOG_HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+"
    r"sshd(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
ISO_HEADER = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d"
    r"(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)\s+"
    r"(?P<hostname>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
AUTH = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>\S+) for "
    r"(?:(?P<invalid>invalid user)\s+)?(?P<username>\S+) from "
    r"(?P<ip>[\w:.%-]+)(?: port (?P<port>\d+))?(?: ssh2)?\b",
    re.IGNORECASE,
)
INVALID_USER = re.compile(r"^Invalid user\s+(?P<username>\S+)\s+from\s+(?P<ip>[\w:.%-]+)")
INVALID_USER_CONTEXT = re.compile(r"^Invalid user\s+(?P<username>\S+)(?:\s+from\s+(?P<ip>\S+))?")
PAM_FAILURE = re.compile(r"pam_unix\(sshd:auth\): authentication failure;", re.IGNORECASE)
PAM_RHOST = re.compile(r"(?:^|\s)rhost=(?P<ip>\S+)")
PAM_USER = re.compile(r"(?:^|\s)user=(?P<username>\S+)")
INPUT_USERAUTH_REQUEST = re.compile(r"^input_userauth_request:", re.IGNORECASE)
INPUT_USERAUTH_USER = re.compile(r"(?:invalid user|for user)\s+(?P<username>\S+)", re.IGNORECASE)
SSH_SESSION = re.compile(
    r"^pam_unix\(sshd:session\): session (?P<state>opened|closed) "
    r"for user (?P<username>\S+)(?: by .*)?$",
    re.IGNORECASE,
)
SSH_SESSION_INTENT = re.compile(r"pam_unix\(sshd:session\):\s*session\b", re.IGNORECASE)
IP_ONLY = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)")
IDENTIFICATION_MISSING = re.compile(
    r"^Did not receive identification string(?: from (?P<source>\S+))?", re.IGNORECASE
)
REPEATED_MESSAGE = re.compile(
    r"^message repeated (?P<count>\d+) times:\s*\[(?P<message>.*)\]$", re.IGNORECASE
)
MAX_REPEATED_OCCURRENCES = 1_000_000
MAX_MALFORMED_SAMPLES = 100
AUTH_INTENT = re.compile(
    r"(?:Failed|Accepted)\s+\S+\s+for\b|Invalid user\b|"
    r"pam_unix\(sshd:auth\): authentication failure|input_userauth_request:",
    re.IGNORECASE,
)


def _event(
    timestamp: datetime,
    hostname: str,
    pid: str | None,
    username: str | None,
    source_ip: str | None,
    port: str | None,
    event_type: str,
    invalid_user: bool = False,
    occurrence_count: int = 1,
    authentication_method: str | None = None,
    context_kind: str | None = None,
) -> dict[str, Any]:
    """Build the stable event shape used by detection rules."""
    return {
        "timestamp": timestamp,
        "hostname": hostname,
        "process_id": int(pid) if pid else None,
        "username": username,
        "source_ip": source_ip,
        "source_attribution": "direct" if source_ip else "unattributed",
        "source_port": int(port) if port else None,
        "event_type": event_type,
        "invalid_user": invalid_user,
        "is_root": username == "root",
        "occurrence_count": occurrence_count,
        "authentication_method": authentication_method,
        "context_kind": context_kind,
    }


def parse_log_line(line: str, year: int | None = None) -> dict[str, Any] | None:
    """Parse one supported SSH log line; return ``None`` for other lines.

    ISO timestamps with offsets are converted to naive UTC so mixed timestamp
    styles can be compared safely. Syslog timestamps are initially assigned
    the supplied year; file-level rollover is handled by :func:`parse_log_file`.
    """
    raw = line.strip()
    match = SYSLOG_HEADER.match(raw)
    if match:
        values = match.groupdict()
        try:
            timestamp = datetime.strptime(
                f"{year or datetime.now().year} {values['month']} {values['day']} {values['clock']}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return None
        if values.get("pid"):
            try:
                int(values["pid"])
            except ValueError:
                return None
    else:
        match = ISO_HEADER.match(raw)
        if not match:
            return None
        values = match.groupdict()
        try:
            timestamp = datetime.fromisoformat(values["timestamp"].replace("Z", "+00:00"))
            if timestamp.tzinfo:
                timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            return None
        if values.get("pid"):
            try:
                int(values["pid"])
            except ValueError:
                return None

    message = values["message"]
    occurrence_count = 1
    repeated = REPEATED_MESSAGE.match(message)
    if repeated:
        try:
            occurrence_count = int(repeated.group("count"))
        except ValueError:
            return None
        if not 1 <= occurrence_count <= MAX_REPEATED_OCCURRENCES:
            return None
        message = repeated.group("message").strip()
    common = (timestamp, values["hostname"], values.get("pid"))
    auth = AUTH.match(message)
    if auth:
        record = auth.groupdict()
        if not _valid_ip(record["ip"]):
            return None
        if record["port"]:
            try:
                int(record["port"])
            except ValueError:
                return None
        return _event(
            *common,
            record["username"],
            record["ip"],
            record["port"],
            "authentication_success"
            if record["result"].lower() == "accepted"
            else "authentication_failure",
            bool(record["invalid"]),
            occurrence_count=occurrence_count,
            authentication_method=record["method"],
        )

    invalid = INVALID_USER_CONTEXT.match(message)
    if invalid:
        record = invalid.groupdict()
        source_ip = record.get("ip")
        if source_ip and not _valid_ip(source_ip):
            return None
        return _event(
            *common,
            record["username"],
            source_ip,
            None,
            "authentication_context",
            True,
            occurrence_count=occurrence_count,
            context_kind="invalid_user",
        )

    pam = PAM_FAILURE.search(message)
    if pam:
        source_match = PAM_RHOST.search(message)
        source_value = source_match.group("ip") if source_match else None
        source_ip = source_value if source_value and _valid_ip(source_value) else None
        user_match = PAM_USER.search(message)
        username = user_match.group("username") if user_match else None
        return _event(
            *common,
            username,
            source_ip,
            None,
            "authentication_context",
            occurrence_count=occurrence_count,
            context_kind="pam_authentication_failure",
        )

    if INPUT_USERAUTH_REQUEST.match(message):
        user_match = INPUT_USERAUTH_USER.search(message)
        username = user_match.group("username") if user_match else None
        return _event(
            *common,
            username,
            None,
            None,
            "authentication_context",
            "invalid user" in message.casefold(),
            occurrence_count=occurrence_count,
            context_kind="input_userauth_request",
        )

    session = SSH_SESSION.match(message)
    if session:
        return _event(
            *common,
            session.group("username"),
            None,
            None,
            f"session_{session.group('state').lower()}",
            occurrence_count=occurrence_count,
        )

    lowered = message.lower()
    if "connection closed by" in lowered or "received disconnect from" in lowered:
        found = IP_ONLY.search(message)
        return _event(
            *common,
            None,
            found.group("ip") if found else None,
            None,
            "connection_closed",
            occurrence_count=occurrence_count,
        )
    identification = IDENTIFICATION_MISSING.match(message)
    if identification:
        source_value = identification.group("source")
        source_ip = source_value if source_value and _valid_ip(source_value) else None
        return _event(
            *common,
            None,
            source_ip,
            None,
            "identification_missing",
            occurrence_count=occurrence_count,
        )
    if "reverse mapping checking getaddrinfo" in lowered and "possible break-in attempt" in lowered:
        found = IP_ONLY.search(message)
        return _event(
            *common,
            None,
            found.group("ip") if found else None,
            None,
            "suspicious_reverse_mapping",
            occurrence_count=occurrence_count,
        )
    return None


def _valid_ip(value: str) -> bool:
    """Return whether a parsed source value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _malformed_reason(line: str, year: int) -> str:
    """Assign a conservative reason to a line already identified as malformed auth."""
    raw = line.strip()
    header = SYSLOG_HEADER.match(raw)
    if header:
        try:
            datetime.strptime(
                f"{year} {header.group('month')} {header.group('day')} {header.group('clock')}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return "invalid_timestamp"
        if header.group("pid"):
            try:
                int(header.group("pid"))
            except ValueError:
                return "invalid_field_value"
        message = header.group("message")
    else:
        iso = ISO_HEADER.match(raw)
        if not iso:
            return "unsupported_auth_format"
        try:
            datetime.fromisoformat(iso.group("timestamp").replace("Z", "+00:00"))
        except ValueError:
            return "invalid_timestamp"
        if iso.group("pid"):
            try:
                int(iso.group("pid"))
            except ValueError:
                return "invalid_field_value"
        message = iso.group("message")

    repeated = REPEATED_MESSAGE.match(message)
    if repeated:
        try:
            count = int(repeated.group("count"))
        except ValueError:
            return "invalid_repeated_count"
        if not 1 <= count <= MAX_REPEATED_OCCURRENCES:
            return "invalid_repeated_count"
        message = repeated.group("message").strip()

    auth = AUTH.match(message)
    if auth and auth.group("port"):
        try:
            int(auth.group("port"))
        except ValueError:
            return "invalid_field_value"
    if auth and not _valid_ip(auth.group("ip")):
        return "invalid_source_ip"
    invalid = INVALID_USER.match(message)
    if invalid and not _valid_ip(invalid.group("ip")):
        return "invalid_source_ip"
    pam = PAM_FAILURE.search(message)
    if pam:
        pam_source = PAM_RHOST.search(message)
        if pam_source and not _valid_ip(pam_source.group("ip")):
            return "unattributed_context"
    if AUTH_INTENT.search(message):
        return "missing_required_field"
    if SSH_SESSION_INTENT.search(message):
        return "unsupported_auth_format"
    return "unsupported_auth_format"


def parse_log_file(
    file_path: str | Path,
    year: int | None = None,
    *,
    include_malformed_records: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse a file and return ``(events, statistics)``.

    Syslog yearless records are assigned the requested year (or this year),
    incrementing once when the stream rolls from December into January.
    Statistics count every input line and whether it yielded an event.
    """
    base_year = year or datetime.now().year
    events: list[dict[str, Any]] = []
    lines_read = 0
    lines_ignored = 0
    lines_malformed = 0
    malformed_by_reason: dict[str, int] = {}
    malformed_records: list[dict[str, int | str]] = []
    malformed_records_truncated = 0
    previous_month: int | None = None
    inferred_year = base_year
    with Path(file_path).open("r", encoding="utf-8", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            lines_read += 1
            header = SYSLOG_HEADER.match(line.strip())
            if header:
                month = datetime.strptime(header.group("month"), "%b").month
                if previous_month == 12 and month == 1:
                    inferred_year += 1
                previous_month = month
            event = parse_log_line(line, year=inferred_year)
            if event is not None and event["event_type"] in {
                "authentication_failure",
                "authentication_success",
                "authentication_context",
                "session_opened",
                "session_closed",
                "connection_closed",
                "identification_missing",
                "suspicious_reverse_mapping",
            }:
                event["_event_id"] = f"ssh:{line_number}"
                events.append(event)
            elif event is not None:
                lines_ignored += 1
            elif re.search(
                r"(?:Failed|Accepted)\s+\S+\s+for\s+|Invalid user\s+|"
                r"pam_unix\(sshd:auth\): authentication failure|"
                r"input_userauth_request:|Connection closed by|Received disconnect from|"
                r"Did not receive identification string|reverse mapping checking getaddrinfo|"
                r"pam_unix\(sshd:session\):\s*session\b",
                line,
                re.IGNORECASE,
            ):
                lines_malformed += 1
                reason = _malformed_reason(line, inferred_year)
                malformed_by_reason[reason] = malformed_by_reason.get(reason, 0) + 1
                if include_malformed_records:
                    if len(malformed_records) < MAX_MALFORMED_SAMPLES:
                        malformed_records.append({"line_number": line_number, "reason": reason})
                    else:
                        malformed_records_truncated += 1
            else:
                lines_ignored += 1
    events.sort(key=lambda event: (event["timestamp"], event.get("_event_id", "")))
    supporting_evidence_records, unresolved_context_records = _correlate_authentication_context(
        events
    )
    authentication_context_records = sum(
        event["event_type"] == "authentication_context" for event in events
    )
    authentication_context_categories = Counter(
        event.get("context_kind", "unknown")
        for event in events
        if event["event_type"] == "authentication_context"
    )
    parsed_record_categories = Counter(event["event_type"] for event in events)
    unattributed_contextual_records = sum(
        event.get("event_type")
        in {
            "authentication_context",
            "session_opened",
            "session_closed",
            "connection_closed",
            "identification_missing",
            "suspicious_reverse_mapping",
        }
        and event.get("source_attribution", "unattributed") == "unattributed"
        for event in events
    )
    records_without_direct_source_ip = sum(
        event.get("source_attribution", "unattributed") != "direct" for event in events
    )
    effective_authentication_attempts = sum(
        event["occurrence_count"]
        for event in events
        if event["event_type"] in {"authentication_failure", "authentication_success"}
    )
    stats = {
        "lines_read": lines_read,
        "events_parsed": len(events),
        "effective_event_occurrences": effective_event_occurrences(events),
        "effective_authentication_attempts": effective_authentication_attempts,
        "authentication_context_records": authentication_context_records,
        "authentication_context_categories": dict(
            sorted(authentication_context_categories.items())
        ),
        "parsed_record_categories": dict(sorted(parsed_record_categories.items())),
        "records_requiring_contextual_correlation": authentication_context_records,
        "supporting_evidence_records": supporting_evidence_records,
        "unattributed_contextual_records": unattributed_contextual_records,
        "records_without_direct_source_ip": records_without_direct_source_ip,
        "unresolved_or_ambiguous_context_records": unresolved_context_records,
        "lines_ignored": lines_ignored,
        "lines_malformed": lines_malformed,
        "malformed_by_reason": malformed_by_reason,
        **ssh_authentication_counts(events),
    }
    if include_malformed_records:
        stats["malformed_records"] = malformed_records
        stats["malformed_records_truncated"] = malformed_records_truncated
    logger.info(
        "Parsed %d authentication events, ignored %d non-auth lines, "
        "and found %d malformed auth lines in %d lines",
        len(events),
        lines_ignored,
        lines_malformed,
        lines_read,
    )
    return events, stats


def _correlate_authentication_context(
    events: list[dict[str, Any]], *, maximum_gap_seconds: int = 10
) -> tuple[int, int]:
    """Attach context to one defensible terminal outcome without changing its count.

    Host, sshd PID, username, compatible source IP, and a maximum ten-second
    timestamp distance are required. If multiple outcomes qualify, evidence is
    left unlinked rather than guessed.
    """
    terminal_by_identity: dict[tuple[str, int, str], list[dict[str, Any]]] = defaultdict(list)
    terminal_by_source: dict[tuple[str, int, str, str | None], list[dict[str, Any]]] = defaultdict(
        list
    )
    for event in events:
        if event.get("event_type") not in {"authentication_failure", "authentication_success"}:
            continue
        hostname = event.get("hostname")
        process_id = event.get("process_id")
        username = event.get("username")
        if not hostname or process_id is None or not username:
            continue
        identity = (hostname, process_id, username)
        terminal_by_identity[identity].append(event)
        terminal_by_source[(*identity, event.get("source_ip"))].append(event)
    for group in terminal_by_identity.values():
        group.sort(key=lambda event: event["timestamp"])
    for group in terminal_by_source.values():
        group.sort(key=lambda event: event["timestamp"])
    terminal_times = {
        key: [event["timestamp"] for event in group] for key, group in terminal_by_identity.items()
    }
    source_times = {
        key: [event["timestamp"] for event in group] for key, group in terminal_by_source.items()
    }

    supporting = 0
    unresolved = 0
    for context in events:
        if context.get("event_type") != "authentication_context":
            continue
        if not context.get("username") or context.get("process_id") is None:
            unresolved += 1
            continue
        identity = (context["hostname"], context["process_id"], context["username"])
        if context.get("source_ip"):
            keys = (
                (*identity, context["source_ip"]),
                (*identity, None),
            )
        else:
            keys = (identity,)
        first_time = context["timestamp"] - timedelta(seconds=maximum_gap_seconds)
        last_time = context["timestamp"] + timedelta(seconds=maximum_gap_seconds)
        candidates = []
        for key in keys:
            if context.get("source_ip"):
                group = terminal_by_source.get(key, [])
                times = source_times.get(key, [])
            else:
                group = terminal_by_identity.get(key, [])
                times = terminal_times.get(key, [])
            first = bisect_left(times, first_time)
            last = bisect_right(times, last_time)
            for outcome in group[first:last]:
                if (
                    not context.get("source_ip")
                    or not outcome.get("source_ip")
                    or context["source_ip"] == outcome["source_ip"]
                ):
                    candidates.append(outcome)
                    if len(candidates) > 1:
                        break
            if len(candidates) > 1:
                break
        if len(candidates) != 1:
            unresolved += 1
            continue
        outcome = candidates[0]
        evidence = {
            "event_id": context["_event_id"],
            "event_type": "authentication_context",
            "context_kind": context.get("context_kind")
            or ("invalid_user" if context.get("invalid_user") else "pam_authentication_failure"),
            "timestamp": context["timestamp"],
            "source_ip": context.get("source_ip") or outcome.get("source_ip"),
        }
        outcome.setdefault("supporting_evidence", []).append(evidence)
        context["correlated_attempt_id"] = outcome["_event_id"]
        if not context.get("source_ip") and outcome.get("source_ip"):
            context["source_ip"] = outcome["source_ip"]
            context["source_attribution"] = "correlated"
        supporting += 1
    return supporting, unresolved
