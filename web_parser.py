"""Parse Nginx/Apache combined access-log records without network access."""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from event_accounting import effective_event_occurrences

logger = logging.getLogger(__name__)

COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<bytes>\d+|-) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"\s*$'
)
MAX_MALFORMED_SAMPLES = 100


def _malformed_reason(line: str) -> str:
    """Classify common combined-log failures without exposing the raw record."""
    match = COMBINED.match(line.strip())
    if not match:
        if line.count('"') % 2 or line.count("[") > line.count("]"):
            return "truncated_record"
        return "unsupported_or_truncated_format"
    values = match.groupdict()
    try:
        ipaddress.ip_address(values["ip"])
    except ValueError:
        return "invalid_ip"
    try:
        datetime.strptime(values["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return "invalid_timestamp"
    if len(values["request"].split()) < 2:
        return "missing_request_fields"
    if values["status"] == "-":
        return "missing_status"
    return "invalid_field_value"


def parse_web_log_line(line: str) -> dict[str, Any] | None:
    """Parse one combined access-log line; return None when it is malformed."""
    match = COMBINED.match(line.strip())
    if not match:
        return None
    values = match.groupdict()
    try:
        address = ipaddress.ip_address(values["ip"])
        timestamp = datetime.strptime(values["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    request = values["request"].split()
    if len(request) < 2:
        return None
    method, path = request[0], request[1]
    if values["status"] == "-":
        return None
    if address.version not in (4, 6):
        return None
    try:
        byte_count = int(values["bytes"]) if values["bytes"] != "-" else 0
    except ValueError:
        return None
    return {
        "timestamp": timestamp.astimezone(timezone.utc).replace(tzinfo=None),
        "hostname": None,
        "process_id": None,
        "username": None,
        "source_ip": str(address),
        "source_port": None,
        "event_type": "web_request",
        "invalid_user": False,
        "is_root": False,
        "method": method,
        "path": path,
        "status": int(values["status"]),
        "bytes": byte_count,
        "referrer": values["referrer"],
        "user_agent": values["user_agent"],
    }


def parse_web_log_file(
    file_path: str | Path, *, include_malformed_records: bool = False
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse a combined access log and return events plus ignored/malformed counts."""
    events = []
    lines_read = 0
    lines_ignored = 0
    lines_malformed = 0
    malformed_by_reason: dict[str, int] = {}
    malformed_records: list[dict[str, int | str]] = []
    malformed_records_truncated = 0
    with Path(file_path).open("r", encoding="utf-8", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            lines_read += 1
            if not line.strip() or line.lstrip().startswith("#"):
                lines_ignored += 1
                continue
            event = parse_web_log_line(line)
            if event is None:
                lines_malformed += 1
                reason = _malformed_reason(line)
                malformed_by_reason[reason] = malformed_by_reason.get(reason, 0) + 1
                if include_malformed_records:
                    if len(malformed_records) < MAX_MALFORMED_SAMPLES:
                        malformed_records.append({"line_number": line_number, "reason": reason})
                    else:
                        malformed_records_truncated += 1
            else:
                event["_event_id"] = f"web:{line_number}"
                events.append(event)
    events.sort(key=lambda event: event["timestamp"])
    stats = {
        "lines_read": lines_read,
        "events_parsed": len(events),
        "effective_event_occurrences": effective_event_occurrences(events),
        "lines_ignored": lines_ignored,
        "lines_malformed": lines_malformed,
        "malformed_by_reason": malformed_by_reason,
    }
    if include_malformed_records:
        stats["malformed_records"] = malformed_records
        stats["malformed_records_truncated"] = malformed_records_truncated
    logger.info(
        "Parsed %d web requests, ignored %d lines, and found %d malformed lines in %d lines",
        len(events),
        lines_ignored,
        lines_malformed,
        lines_read,
    )
    return events, stats
