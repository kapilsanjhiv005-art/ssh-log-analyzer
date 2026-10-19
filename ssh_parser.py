"""Parse common OpenSSH authentication and connection log messages."""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
INVALID_USER = re.compile(r"^Invalid user (?P<username>\S+) from (?P<ip>[\w:.%-]+)")
PAM_FAILURE = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure;.*?"
    r"(?:rhost=(?P<ip>\S+)).*?(?:user=(?P<username>\S+))?"
)
PAM_USER = re.compile(r"(?:^|\s)user=(?P<username>\S+)")
IP_ONLY = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)")
REPEATED_MESSAGE = re.compile(
    r"^message repeated (?P<count>\d+) times:\s*\[(?P<message>.*)\]$", re.IGNORECASE
)
MAX_REPEATED_OCCURRENCES = 1_000_000


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
) -> dict[str, Any]:
    """Build the stable event shape used by detection rules."""
    return {
        "timestamp": timestamp,
        "hostname": hostname,
        "process_id": int(pid) if pid else None,
        "username": username,
        "source_ip": source_ip,
        "source_port": int(port) if port else None,
        "event_type": event_type,
        "invalid_user": invalid_user,
        "is_root": username == "root",
        "occurrence_count": occurrence_count,
        "authentication_method": authentication_method,
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

    message = values["message"]
    occurrence_count = 1
    repeated = REPEATED_MESSAGE.match(message)
    if repeated:
        occurrence_count = int(repeated.group("count"))
        if not 1 <= occurrence_count <= MAX_REPEATED_OCCURRENCES:
            return None
        message = repeated.group("message").strip()
    common = (timestamp, values["hostname"], values.get("pid"))
    auth = AUTH.match(message)
    if auth:
        record = auth.groupdict()
        if not _valid_ip(record["ip"]):
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

    invalid = INVALID_USER.match(message)
    if invalid:
        record = invalid.groupdict()
        if not _valid_ip(record["ip"]):
            return None
        return _event(
            *common,
            record["username"],
            record["ip"],
            None,
            "authentication_failure",
            True,
            occurrence_count=occurrence_count,
        )

    pam = PAM_FAILURE.search(message)
    if pam:
        record = pam.groupdict()
        if not _valid_ip(record["ip"]):
            return None
        user_match = PAM_USER.search(message)
        username = record.get("username") or (user_match.group("username") if user_match else None)
        return _event(
            *common,
            username,
            record["ip"],
            None,
            "authentication_failure",
            occurrence_count=occurrence_count,
        )

    lowered = message.lower()
    if "connection closed by" in lowered or "received disconnect from" in lowered:
        found = IP_ONLY.search(message)
        if found:
            return _event(
                *common,
                None,
                found.group("ip"),
                None,
                "connection_closed",
                occurrence_count=occurrence_count,
            )
    if "reverse mapping checking getaddrinfo" in lowered and "possible break-in attempt" in lowered:
        found = IP_ONLY.search(message)
        if found:
            return _event(
                *common,
                None,
                found.group("ip"),
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


def parse_log_file(
    file_path: str | Path, year: int | None = None
) -> tuple[list[dict[str, Any]], dict[str, int]]:
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
            if event is not None and event["event_type"].startswith("authentication_"):
                event["_event_id"] = f"ssh:{line_number}"
                events.append(event)
            elif event is not None:
                lines_ignored += 1
            elif re.search(
                r"(?:Failed|Accepted)\s+\S+\s+for\s+|Invalid user\s+|"
                r"pam_unix\(sshd:auth\): authentication failure",
                line,
                re.IGNORECASE,
            ):
                lines_malformed += 1
            else:
                lines_ignored += 1
    events.sort(key=lambda event: event["timestamp"])
    stats = {
        "lines_read": lines_read,
        "events_parsed": len(events),
        "lines_ignored": lines_ignored,
        "lines_malformed": lines_malformed,
    }
    logger.info(
        "Parsed %d authentication events, ignored %d non-auth lines, "
        "and found %d malformed auth lines in %d lines",
        len(events),
        lines_ignored,
        lines_malformed,
        lines_read,
    )
    return events, stats
