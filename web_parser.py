"""Parse Nginx/Apache combined access-log records without network access."""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<bytes>\d+|-) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"\s*$'
)


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
        "bytes": int(values["bytes"]) if values["bytes"] != "-" else 0,
        "referrer": values["referrer"],
        "user_agent": values["user_agent"],
    }


def parse_web_log_file(file_path: str | Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse a combined access log and return events plus ignored/malformed counts."""
    events = []
    lines_read = 0
    lines_ignored = 0
    lines_malformed = 0
    with Path(file_path).open("r", encoding="utf-8", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            lines_read += 1
            if not line.strip() or line.lstrip().startswith("#"):
                lines_ignored += 1
                continue
            event = parse_web_log_line(line)
            if event is None:
                lines_malformed += 1
            else:
                event["_event_id"] = f"web:{line_number}"
                events.append(event)
    events.sort(key=lambda event: event["timestamp"])
    stats = {
        "lines_read": lines_read,
        "events_parsed": len(events),
        "lines_ignored": lines_ignored,
        "lines_malformed": lines_malformed,
    }
    logger.info(
        "Parsed %d web requests, ignored %d lines, and found %d malformed lines in %d lines",
        len(events),
        lines_ignored,
        lines_malformed,
        lines_read,
    )
    return events, stats
