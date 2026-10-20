"""Local Streamlit dashboard for authorized SSH and web log analysis."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any

import altair as alt

from analyzer import (
    VERSION,
    _output_value,
    load_input,
    render_csv,
    render_successful_logins_csv,
    timestamp_interpretation,
)
from config import load_config
from detections import (
    analyze_events,
    calculate_risk_explanations,
    calculate_risk_scores,
    correlate_incidents,
)
from event_accounting import effective_event_occurrences, event_occurrences
from investigation import build_successful_login_rows

PROJECT_DIR = Path(__file__).resolve().parent
SAMPLE_LOGS = {
    "SSH sample": PROJECT_DIR / "sample_logs" / "auth.log",
    "Web sample": PROJECT_DIR / "sample_logs" / "web_access.log",
}
SEVERITIES = ("Critical", "High", "Medium", "Low")
THEME_COLORS = {
    "background": "#070b16",
    "surface": "#0b1120",
    "panel": "#10192b",
    "panel_alt": "#131f35",
    "elevated": "#17253d",
    "border": "#243651",
    "border_subtle": "#1c2b42",
    "text": "#edf4ff",
    "text_secondary": "#a7b7cc",
    "text_muted": "#7487a2",
    "cyan": "#36d7f5",
    "teal": "#35e0c1",
    "blue": "#548cff",
    "violet": "#9b7bff",
    "magenta": "#f06bd8",
    "green": "#40d9a2",
    "amber": "#ffc76a",
    "orange": "#ff925c",
    "critical": "#ff5d73",
}
PAGE_DISPLAY_NAMES = {
    "Overview": "Security Operations Overview",
    "Alerts": "Alert Triage",
    "Incidents": "Incident Investigation",
    "Sources": "Source Intelligence",
    "Timeline": "Security Event Timeline",
    "Successful Logins": "Successful Login Review",
    "Detection Coverage": "Detection Coverage",
    "Data Quality": "Data Quality and Parser Diagnostics",
    "Reports": "Analysis Reports",
    "Settings": "Analysis Configuration",
    "Detailed Analysis": "Detailed Analysis",
}
PAGE_SUBTITLES = {
    "Overview": "Local security telemetry, detections, and risk at a glance.",
    "Alerts": "Triage rule findings and inspect the supporting evidence.",
    "Incidents": "Investigate correlated alerts and their preserved evidence.",
    "Sources": "Review observed source activity and existing risk scores.",
    "Timeline": "Explore parsed timestamps and filter by interval.",
    "Successful Logins": "Review successful authentications and cautiously linked session evidence.",
    "Detection Coverage": "Implemented rules, required evidence, and known limits.",
    "Data Quality": "Parser accounting, format coverage, and diagnostics.",
    "Reports": "Export the current analysis without sending data externally.",
    "Settings": "Validated configuration and session-scoped overrides.",
    "Detailed Analysis": "Full analysis context, event coverage, and exports.",
}
RISK_COLORS = {
    "Low": "green",
    "Medium": "yellow",
    "High": "orange",
    "Critical": "red",
}
RISK_CHART_COLORS = {
    "Low": THEME_COLORS["cyan"],
    "Medium": THEME_COLORS["amber"],
    "High": THEME_COLORS["orange"],
    "Critical": THEME_COLORS["critical"],
}
SETTING_ICONS = {
    "SSH brute force": "🔐",
    "Low-and-slow SSH": "🕰️",
    "Multi-account guessing": "👥",
    "Invalid-user probing": "🧭",
    "Distributed brute force": "🌐",
    "Root authentication": "🛡️",
    "Success after failures": "⚠️",
    "New-source policy": "📍",
    "Alert merging": "🧩",
    "Severity escalation": "🚦",
    "Business hours": "🕒",
    "Web detections": "🌍",
}


def risk_band_badge(band: str) -> dict[str, str]:
    """Return a validated label and Streamlit badge color without HTML markup."""
    label = band if band in RISK_COLORS else "Unknown"
    return {"label": label, "color": RISK_COLORS.get(label, "gray")}


def _severity_symbol(severity: str | None) -> str:
    """Return a visible text symbol for table severity without replacing its label."""
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(str(severity), "⚪")


def _risk_band_symbol(band: str | None) -> str:
    """Return the matching visible symbol for a source risk band."""
    return _severity_symbol(band)


def malformed_summary_rows(parse_stats: dict[str, Any]) -> list[dict[str, Any]]:
    """Return sorted malformed-reason totals for safe dashboard rendering."""
    return [
        {"Reason": reason, "Lines": count}
        for reason, count in sorted(parse_stats.get("malformed_by_reason", {}).items())
    ]


def dashboard_markdown_without_links(markdown: str) -> str:
    """Render documentation text without links that can navigate away from the local app."""
    return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", markdown)


def data_quality_metrics(
    parse_stats: dict[str, Any], events: list[dict[str, Any]]
) -> list[tuple[str, str | int]]:
    """Return physical-line, parsed-record, and weighted-event quality metrics."""
    lines = parse_stats.get("lines_read", 0)
    malformed = parse_stats.get("lines_malformed", 0)
    effective = parse_stats.get("effective_event_occurrences", effective_event_occurrences(events))
    malformed_rate = f"{100 * malformed / lines:.1f}%" if lines else "0.0%"
    return [
        ("Lines read", lines),
        ("Parsed records", parse_stats.get("events_parsed", 0)),
        ("Effective occurrences", effective),
        ("Ignored", parse_stats.get("lines_ignored", 0)),
        ("Malformed", malformed),
        ("Malformed rate", malformed_rate),
    ]


def data_quality_sections(
    parse_stats: dict[str, Any], events: list[dict[str, Any]], *, log_type: str
) -> list[tuple[str, list[tuple[str, str | int]]]]:
    """Group existing parser counters by accounting purpose without conflating them."""
    metrics = dict(data_quality_metrics(parse_stats, events))
    input_accounting = [
        ("Lines read", metrics["Lines read"]),
        ("Parsed records", metrics["Parsed records"]),
        ("Ignored lines", metrics["Ignored"]),
        ("Malformed lines", metrics["Malformed"]),
    ]
    event_accounting = [("Effective occurrences", metrics["Effective occurrences"])]
    sections = [
        ("Input accounting", input_accounting),
        ("Event accounting", event_accounting),
    ]
    if log_type == "ssh":
        sections.append(
            (
                "Authentication attempts",
                [
                    (
                        "Terminal authentication attempts",
                        parse_stats.get("effective_authentication_attempts", 0),
                    ),
                    (
                        "Failed authentication attempts (all methods)",
                        parse_stats.get("authentication_failures", 0),
                    ),
                    (
                        "Failed password attempts",
                        parse_stats.get("password_authentication_failures", 0),
                    ),
                    (
                        "Authentication-method probes (Failed none)",
                        parse_stats.get("authentication_method_probes", 0),
                    ),
                    (
                        "Successful authentication attempts",
                        parse_stats.get("authentication_successes", 0),
                    ),
                    (
                        "Failed root authentication attempts (all methods)",
                        parse_stats.get("root_authentication_failures", 0),
                    ),
                    (
                        "Failed root password attempts",
                        parse_stats.get("root_password_authentication_failures", 0),
                    ),
                    (
                        "Successful root authentication attempts",
                        parse_stats.get("root_authentication_successes", 0),
                    ),
                    (
                        "Supporting authentication context records",
                        parse_stats.get("authentication_context_records", 0),
                    ),
                    (
                        "Context records linked to one outcome",
                        parse_stats.get("supporting_evidence_records", 0),
                    ),
                    (
                        "Unattributed contextual records",
                        parse_stats.get("unattributed_contextual_records", 0),
                    ),
                    (
                        "Records without direct source IP",
                        parse_stats.get("records_without_direct_source_ip", 0),
                    ),
                    (
                        "Unresolved or ambiguous context records",
                        parse_stats.get("unresolved_or_ambiguous_context_records", 0),
                    ),
                ],
            )
        )
    if log_type == "ssh":
        context_categories = parse_stats.get("authentication_context_categories", {})
        record_categories = parse_stats.get("parsed_record_categories", {})
        context_rows = [
            ("Invalid-user context records", context_categories.get("invalid_user", 0)),
            (
                "PAM authentication-failure context records",
                context_categories.get("pam_authentication_failure", 0),
            ),
            (
                "input_userauth_request records",
                context_categories.get("input_userauth_request", 0),
            ),
            ("Connection-closed records", record_categories.get("connection_closed", 0)),
            (
                "Identification-missing records",
                record_categories.get("identification_missing", 0),
            ),
            (
                "Reverse-mapping notices",
                record_categories.get("suspicious_reverse_mapping", 0),
            ),
            ("Session-open records", record_categories.get("session_opened", 0)),
            ("Session-close records", record_categories.get("session_closed", 0)),
        ]
        sections.append(("SSH context and probes", context_rows))
    lines = parse_stats.get("lines_read", 0)
    malformed = parse_stats.get("lines_malformed", 0)
    malformed_rate = f"{100 * malformed / lines:.1f}%" if lines else "0.0%"
    formats = (
        "OpenSSH/syslog authentication log"
        if log_type == "ssh"
        else "Nginx/Apache combined access log"
    )
    reasons = parse_stats.get("malformed_by_reason", {})
    health: list[tuple[str, str | int]] = [
        ("Malformed percentage", malformed_rate),
        ("Supported format", formats),
        (
            "Malformed reasons",
            ", ".join(f"{reason}: {count}" for reason, count in sorted(reasons.items())) or "None",
        ),
    ]
    sections.append(("Parser health", health))
    return sections


def detection_inventory_rows(markdown: str) -> list[dict[str, str]]:
    """Parse documented rule inventory rows into analyst fields and traceability refs."""
    rows = []
    for line in markdown.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 7:
            continue
        match = re.fullmatch(r"`([^`]+)`\s*[—-]\s*(.+)", cells[0])
        if match is None:
            continue
        tests = cells[5]
        rows.append(
            {
                "Rule": match.group(1),
                "Detection": match.group(2),
                "Severity": cells[3],
                "Threshold/window": cells[1],
                "MITRE ATT&CK": cells[4],
                "Required evidence": cells[2],
                "Known limitations": cells[6],
                "Test references": tests,
                "Validation status": "Test references documented"
                if tests and tests != "—"
                else "No test references documented",
            }
        )
    return rows


def detection_summary_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return only scan-friendly analyst fields for the primary rule table."""
    return [
        {
            "Rule ID": row["Rule"],
            "Detection": row["Detection"],
            "Base severity": row["Severity"].split(";")[0].strip(),
        }
        for row in rows
    ]


def settings_value_rows(values: list[tuple[str, Any]]) -> list[dict[str, str]]:
    """Format validated configuration pairs as compact, readable table rows."""
    rows = []
    for key, value in values:
        label = key.replace("_", " ").capitalize()
        formatted = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
        rows.append({"Setting": label, "Configured value": formatted})
    return rows


def source_risk_rows(
    risk_scores: dict[str, dict[str, Any]],
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    *,
    log_type: str,
) -> list[dict[str, Any]]:
    """Build compact source rows with risk, time bounds, alert counts, and real outcomes."""
    rows = []
    for source_ip, risk in sorted(
        risk_scores.items(), key=lambda item: (-item[1]["score"], item[0])
    ):
        source_events = [event for event in events if event.get("source_ip") == source_ip]
        timestamps = [
            stamp
            for event in source_events
            if (stamp := _as_datetime(event.get("timestamp"))) is not None
        ]
        failure_label, failures, success_label, successes = source_outcome_counts(
            source_events, log_type=log_type
        )
        rows.append(
            {
                "Source IP": source_ip,
                "Risk score": risk["score"],
                "Risk band": risk["band"],
                "Alerts": sum(
                    source_ip == alert.get("source_ip") or source_ip in alert.get("source_ips", [])
                    for alert in alerts
                ),
                "Incidents": sum(source_ip == item.get("source_ip") for item in incidents),
                "First seen (parsed timestamp)": min(timestamps) if timestamps else None,
                "Last seen (parsed timestamp)": max(timestamps) if timestamps else None,
                f"{failure_label} attempts" if log_type == "ssh" else failure_label: failures,
                f"{success_label} attempts" if log_type == "ssh" else success_label: successes,
            }
        )
    return rows


def settings_sections(config: dict[str, Any]) -> list[tuple[str, list[tuple[str, Any]]]]:
    """Organize the validated configuration into user-facing detection groups."""
    config_groups = [
        ("SSH brute force", "brute_force"),
        ("Low-and-slow SSH", "low_and_slow"),
        ("Multi-account guessing", "password_spraying"),
        ("Invalid-user probing", "username_enumeration"),
        ("Distributed brute force", "distributed_bruteforce"),
        ("Root authentication", "root_attempts"),
        ("Success after failures", "success_after_failures"),
        ("New-source policy", "new_source_ip"),
        ("Alert merging", "alert_merging"),
        ("Severity escalation", "severity_thresholds"),
        ("Business hours", "off_hours"),
    ]
    sections = [
        (title, sorted(config.get(key, {}).items()))
        for title, key in config_groups
        if isinstance(config.get(key), dict)
    ]
    web = config.get("web")
    if isinstance(web, dict):
        sections.append(("Web detections", sorted(web.items())))
    return sections


def parse_allowlist_text(text: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse optional IP/CIDR allowlist text, ignoring comments and blanks."""
    networks = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as error:
            raise ValueError(f"Invalid IP/CIDR on allowlist line {line_number}: {value}") from error
    return networks


def analyze_for_dashboard(
    log_path: str | Path,
    *,
    log_type: str,
    year: int,
    config: dict[str, Any] | None = None,
    allowlist_text: str = "",
    threshold: int | None = None,
    window_seconds: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    """Parse and analyze one local file using the CLI's shared pipeline."""
    settings = load_config(None) if config is None else config
    settings = {
        section: value.copy() if isinstance(value, dict) else value
        for section, value in settings.items()
    }
    if threshold is not None:
        if log_type == "ssh":
            settings["brute_force"]["threshold"] = threshold
        else:
            settings["web"]["login_threshold"] = threshold
            settings["web"]["scanning_404_threshold"] = threshold
    if window_seconds is not None:
        if log_type == "ssh":
            settings["brute_force"]["window_seconds"] = window_seconds
        else:
            settings["web"]["login_window_seconds"] = window_seconds
            settings["web"]["scanning_window_seconds"] = window_seconds
            settings["web"]["user_agent_window_seconds"] = window_seconds
    events, parse_stats = load_input(log_path, log_type, year, include_malformed_records=True)
    result = analyze_events(
        events,
        config=settings,
        allowlist=parse_allowlist_text(allowlist_text) if allowlist_text.strip() else None,
        log_type=log_type,
    )
    result.update(
        {
            "config_used": settings,
            "parse_stats": parse_stats,
            "version": VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "timestamp_interpretation": timestamp_interpretation(log_type, year),
            "successful_logins": (
                build_successful_login_rows(
                    events,
                    result["alerts"],
                    lookback_seconds=settings["success_after_failures"]["lookback_seconds"],
                )
                if log_type == "ssh"
                else []
            ),
        }
    )
    return events, parse_stats, result


def _attempts_by_hour(events: list[dict[str, Any]]) -> dict[datetime, int]:
    """Count failed SSH or web events by hour for the timeline chart."""
    counts: Counter[datetime] = Counter()
    for event in events:
        failed = event.get("event_type") == "authentication_failure" or event.get("status") in (
            401,
            403,
            404,
        )
        if failed:
            timestamp = _as_datetime(event.get("timestamp"))
            if timestamp is None:
                continue
            counts[timestamp.replace(minute=0, second=0, microsecond=0)] += event_occurrences(event)
    return dict(sorted(counts.items()))


def _as_datetime(value: Any) -> datetime | None:
    """Convert an available event timestamp to the parser's naive datetime coordinate."""
    if value is None:
        return None
    try:
        if isinstance(value, datetime):
            timestamp = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            timestamp = datetime.fromtimestamp(value / 1000, timezone.utc).replace(tzinfo=None)
        else:
            timestamp = datetime.fromisoformat(str(value))
    except (OSError, OverflowError, TypeError, ValueError):
        return None
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    return timestamp


def summarize_dashboard_metrics(
    alerts: list[dict[str, Any]],
    risk_scores: dict[str, dict[str, Any]],
    incidents: list[dict[str, Any]],
) -> dict[str, int]:
    """Summarize rule-severity alerts separately from unique source-risk bands."""
    counts = Counter(alert.get("base_severity", alert.get("severity")) for alert in alerts)
    return {
        **{f"{severity.lower()}_alerts": counts.get(severity, 0) for severity in SEVERITIES},
        "critical_risk_sources": sum(
            risk.get("band") == "Critical" for risk in risk_scores.values()
        ),
        "incidents": len(incidents),
    }


def filter_dashboard_data(
    events: list[dict[str, Any]],
    result: dict[str, Any],
    *,
    source_ip: str | None = None,
    start_date: date | None = None,
    end_date: date | None = None,
    severities: set[str] | None = None,
    rules: set[str] | None = None,
    usernames: set[str] | None = None,
    search_query: str = "",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Filter dashboard views without modifying source events or analysis records."""
    has_dates = start_date is not None or end_date is not None
    start = datetime.combine(start_date, time.min) if start_date else None
    end = datetime.combine(end_date, time.max) if end_date else None

    def in_range(first_value: Any, last_value: Any = None) -> bool:
        first = _as_datetime(first_value)
        last = _as_datetime(last_value) or first
        if first is None:
            return not has_dates
        return (end is None or first <= end) and (start is None or (last or first) >= start)

    visible_events = [
        event
        for event in events
        if (source_ip is None or event.get("source_ip") == source_ip)
        and _as_datetime(event.get("timestamp")) is not None
        and in_range(event.get("timestamp"))
    ]
    visible_alerts = []
    normalized_search = search_query.casefold().strip()
    for alert in result.get("alerts", []):
        sources = {alert.get("source_ip"), *alert.get("source_ips", [])}
        if source_ip is not None and source_ip not in sources:
            continue
        if (
            severities is not None
            and alert.get("base_severity", alert.get("severity")) not in severities
        ):
            continue
        if rules is not None and alert.get("rule") not in rules:
            continue
        alert_usernames = set(alert.get("usernames_targeted", []))
        if alert.get("username"):
            alert_usernames.add(alert["username"])
        if alert.get("target_username"):
            alert_usernames.add(alert["target_username"])
        if usernames is not None and not alert_usernames.intersection(usernames):
            continue
        searchable = " ".join(
            str(alert.get(field, ""))
            for field in (
                "rule",
                "source_ip",
                "source_ips",
                "usernames_targeted",
                "username",
                "target_username",
                "description",
                "recommended_action",
                "path",
                "paths",
            )
        ).casefold()
        if normalized_search and normalized_search not in searchable:
            continue
        if in_range(alert.get("first_seen"), alert.get("last_seen")):
            visible_alerts.append(dict(alert))

    risk_scores = calculate_risk_scores(visible_events, visible_alerts)
    for alert in visible_alerts:
        source_risk = risk_scores.get(alert.get("source_ip"))
        if source_risk:
            alert["source_risk_score"] = source_risk["score"]
            alert["source_risk_band"] = source_risk["band"]
            alert["risk_score"] = source_risk["score"]
            alert["risk_band"] = source_risk["band"]
    filtered = dict(result)
    filtered["alerts"] = visible_alerts
    filtered["risk_scores"] = risk_scores
    filtered["risk_explanations"] = calculate_risk_explanations(
        visible_events, visible_alerts, risk_scores
    )
    filtered["successful_logins"] = [
        row
        for row in result.get("successful_logins", [])
        if (source_ip is None or row.get("source_ip") == source_ip)
        and in_range(row.get("timestamp"))
    ]
    incidents = correlate_incidents(visible_alerts, risk_scores)
    original_incidents = result.get("incidents", [])
    for incident in incidents:
        incident_rules = set(incident.get("contributing_rules", []))
        matching_originals = [
            original
            for original in original_incidents
            if original.get("source_ip") == incident.get("source_ip")
            and incident_rules.issubset(set(original.get("contributing_rules", [])))
            and _as_datetime(original.get("first_seen")) is not None
            and _as_datetime(original.get("last_seen")) is not None
            and _as_datetime(incident.get("first_seen")) is not None
            and _as_datetime(incident.get("last_seen")) is not None
            and _as_datetime(original.get("first_seen")) <= _as_datetime(incident.get("last_seen"))
            and _as_datetime(original.get("last_seen")) >= _as_datetime(incident.get("first_seen"))
        ]
        if matching_originals:
            original = matching_originals[0]
            incident["incident_id"] = original["incident_id"]
            for field in ("attempt_count", "usernames_targeted", "authentication_methods"):
                if field in original:
                    incident[field] = original[field]
        else:
            # Do not invent an evidence count by summing every event in a time span.
            incident.pop("attempt_count", None)
    filtered["incidents"] = incidents
    return visible_events, filtered


def timeline_event_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build chronological, source-honest rows for the event timeline page."""
    rows = []
    ordered = sorted(
        (
            (stamp, event)
            for event in events
            if (stamp := _as_datetime(event.get("timestamp"))) is not None
        ),
        key=lambda item: item[0],
    )
    for stamp, event in ordered:
        event_type = event.get("event_type", "web_request")
        source_ip = event.get("source_ip")
        linkage = (
            "Unlinked context"
            if event_type in {"session_opened", "session_closed"} and not source_ip
            else "Source-attributed event"
            if source_ip
            else "Source unavailable"
        )
        detail = event.get("path") or event.get("message") or event.get("authentication_method")
        rows.append(
            {
                "Timestamp (parsed timestamp)": stamp,
                "Event": event_type,
                "Linkage": linkage,
                "Source IP": source_ip,
                "Username": event.get("username"),
                "Method": event.get("authentication_method"),
                "Status": event.get("status"),
                "Detail": detail,
                "Occurrences": event_occurrences(event),
            }
        )
    return rows


def timeline_selection_bounds(selection: dict[str, Any]) -> tuple[datetime, datetime] | None:
    """Return a valid brushed time interval from Streamlit's Altair selection state."""
    interval = selection.get("timeline_brush", {})
    if not isinstance(interval, dict):
        return None
    values = interval.get("hour")
    if not isinstance(values, (tuple, list)) or len(values) != 2:
        return None
    first, last = (_as_datetime(value) for value in values)
    if first is None or last is None:
        return None
    return min(first, last), max(first, last)


def filter_timeline_events(
    events: list[dict[str, Any]], bounds: tuple[datetime, datetime] | None
) -> list[dict[str, Any]]:
    """Filter timeline records to inclusive parsed timestamp bounds, or return all without a brush."""
    if bounds is None:
        return list(events)
    start, end = bounds
    return [
        event
        for event in events
        if (stamp := _as_datetime(event.get("timestamp"))) is not None and start <= stamp <= end
    ]


def source_outcome_counts(
    events: list[dict[str, Any]], *, log_type: str
) -> tuple[str, int, str, int]:
    """Return weighted source outcomes without interpreting web status as authentication."""
    if log_type == "ssh":
        return (
            "Failed SSH",
            sum(
                event_occurrences(event)
                for event in events
                if event.get("event_type") == "authentication_failure"
            ),
            "Successful SSH",
            sum(
                event_occurrences(event)
                for event in events
                if event.get("event_type") == "authentication_success"
            ),
        )
    return (
        "Unauthorized/not-found responses",
        sum(event_occurrences(event) for event in events if event.get("status") in (401, 403, 404)),
        "2xx responses (not auth success)",
        sum(
            event_occurrences(event)
            for event in events
            if isinstance(event.get("status"), int) and 200 <= event["status"] < 300
        ),
    )


def _timeline_chart(events: list[dict[str, Any]]) -> alt.Chart | None:
    """Create an accessible, brush-selectable hourly failed-event chart."""
    hourly = _attempts_by_hour(events)
    if not hourly:
        return None
    values = [
        {
            "hour": f"{stamp.isoformat()}Z",
            "hour_label": f"{stamp:%Y-%m-%d %H:%M}",
            "failed_attempts": count,
        }
        for stamp, count in hourly.items()
    ]
    brush = alt.selection_interval(name="timeline_brush", encodings=["x"], clear="dblclick")
    chart = (
        alt.Chart(alt.Data(values=values))
        .mark_line(point=alt.OverlayMarkDef(filled=True, size=58), color=THEME_COLORS["cyan"])
        .encode(
            x=alt.X(
                "hour:T",
                axis=alt.Axis(
                    formatType="utc",
                    labelExpr="utcFormat(datum.value, '%Y-%m-%d %H:%M')",
                ),
                title="Time (parsed timestamp)",
            ),
            y=alt.Y(
                "failed_attempts:Q", title="Weighted failed events", scale=alt.Scale(zero=True)
            ),
            tooltip=[
                alt.Tooltip("hour_label:N", title="Time (parsed timestamp)"),
                alt.Tooltip("failed_attempts:Q", title="Weighted failed events"),
            ],
        )
        .add_params(brush)
    )
    return _style_chart(chart)


def _overview_attempts_chart(events: list[dict[str, Any]]) -> alt.LayerChart | None:
    """Build a compact parsed timestamp trend chart from weighted failed event occurrences."""
    values = [
        {"hour": f"{stamp.isoformat()}Z", "failed_attempts": count}
        for stamp, count in _attempts_by_hour(events).items()
    ]
    if not values:
        return None
    base = alt.Chart(alt.Data(values=values)).encode(
        x=alt.X(
            "hour:T",
            title="Time (parsed timestamp)",
            axis=alt.Axis(
                formatType="utc",
                labelExpr="utcFormat(datum.value, '%b %d %H:%M')",
                labelAngle=0,
                tickCount=6,
            ),
        ),
        y=alt.Y(
            "failed_attempts:Q",
            title="Weighted failed events",
            scale=alt.Scale(zero=True),
        ),
        tooltip=[
            alt.Tooltip("hour:T", title="Time", format="%Y-%m-%d %H:%M"),
            alt.Tooltip("failed_attempts:Q", title="Failed events", format=","),
        ],
    )
    chart = (
        base.mark_area(color=THEME_COLORS["teal"], opacity=0.14)
        + base.mark_line(color=THEME_COLORS["cyan"], point=alt.OverlayMarkDef(filled=True, size=58))
    ).properties(height=270, title="Failed activity by hour")
    return _style_chart(chart)


def _detailed_attempts_chart(
    events: list[dict[str, Any]], *, log_scale: bool = False
) -> alt.Chart | alt.LayerChart | None:
    """Build an interactive weighted failure timeline with exact hourly tooltips."""
    values = [
        {"hour": f"{stamp.isoformat()}Z", "failed_attempts": count}
        for stamp, count in _attempts_by_hour(events).items()
    ]
    if not values:
        return None
    y_scale = alt.Scale(type="log", domainMin=1) if log_scale else alt.Scale(zero=True)
    base = alt.Chart(alt.Data(values=values)).encode(
        x=alt.X(
            "hour:T",
            title="Time (parsed timestamp)",
            axis=alt.Axis(
                formatType="utc",
                labelExpr="utcFormat(datum.value, '%b %d %H:%M')",
                labelAngle=0,
            ),
        ),
        y=alt.Y("failed_attempts:Q", title="Weighted failed events", scale=y_scale),
        tooltip=[
            alt.Tooltip("hour:T", title="Time", format="%Y-%m-%d %H:%M"),
            alt.Tooltip("failed_attempts:Q", title="Failed events", format=","),
        ],
    )
    if log_scale:
        chart = base.mark_line(
            color=THEME_COLORS["cyan"], point=alt.OverlayMarkDef(filled=True, size=58)
        )
    else:
        chart = base.mark_area(color=THEME_COLORS["teal"], opacity=0.14) + base.mark_line(
            color=THEME_COLORS["cyan"], point=alt.OverlayMarkDef(filled=True, size=58)
        )
    return _style_chart(chart.properties(height=290, title="Failed activity by hour").interactive())


def _detailed_source_activity_chart(
    events: list[dict[str, Any]], *, limit: int = 5
) -> alt.Chart | alt.LayerChart | None:
    """Build an interactive, weighted top-source timeline from observed failures."""
    by_source: dict[str, Counter[datetime]] = defaultdict(Counter)
    for event in events:
        failed = event.get("event_type") == "authentication_failure" or event.get("status") in (
            401,
            403,
            404,
        )
        source_ip = event.get("source_ip")
        timestamp = _as_datetime(event.get("timestamp"))
        if not failed or not source_ip or timestamp is None:
            continue
        hour = timestamp.replace(minute=0, second=0, microsecond=0)
        by_source[source_ip][hour] += event_occurrences(event)
    top_sources = [
        source_ip
        for source_ip, _ in sorted(
            by_source.items(), key=lambda pair: (-sum(pair[1].values()), pair[0])
        )[:limit]
    ]
    if not top_sources:
        return None
    values = [
        {
            "source_ip": source_ip,
            "hour": f"{hour.isoformat()}Z",
            "failed_attempts": count,
        }
        for source_ip in top_sources
        for hour, count in sorted(by_source[source_ip].items())
    ]
    chart = (
        alt.Chart(alt.Data(values=values))
        .mark_line(point=alt.OverlayMarkDef(filled=True, size=46))
        .encode(
            x=alt.X(
                "hour:T",
                title="Time (parsed timestamp)",
                axis=alt.Axis(
                    formatType="utc",
                    labelExpr="utcFormat(datum.value, '%b %d %H:%M')",
                    labelAngle=-25,
                    tickCount=6,
                ),
            ),
            y=alt.Y(
                "failed_attempts:Q", title="Weighted failed events", scale=alt.Scale(zero=True)
            ),
            color=alt.Color(
                "source_ip:N",
                title="Source IP",
                scale=alt.Scale(scheme="tableau20"),
            ),
            tooltip=[
                alt.Tooltip("source_ip:N", title="Source IP"),
                alt.Tooltip("hour:T", title="Time", format="%Y-%m-%d %H:%M"),
                alt.Tooltip("failed_attempts:Q", title="Failed events", format=","),
            ],
        )
        .properties(height=310, title=f"Failed activity by source · Top {len(top_sources)}")
        .interactive(bind_y=False)
    )
    return _style_chart(chart)


def related_activity_rows(
    alerts: list[dict[str, Any]], selected_alert: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return advisory peer alerts with an explicitly shared source identifier."""
    selected_sources = {
        source
        for source in [
            selected_alert.get("source_ip"),
            *(selected_alert.get("source_ips") or []),
        ]
        if isinstance(source, str) and source
    }
    if not selected_sources:
        return []
    rows = []
    for alert in alerts:
        if alert is selected_alert:
            continue
        candidate_sources = {
            source
            for source in [alert.get("source_ip"), *(alert.get("source_ips") or [])]
            if isinstance(source, str) and source
        }
        shared_sources = sorted(selected_sources & candidate_sources)
        if not shared_sources:
            continue
        rows.append(
            {
                "Rule": alert.get("rule", "Unknown"),
                "Severity": alert.get("base_severity", alert.get("severity", "Unknown")),
                "Source IP": ", ".join(shared_sources),
                "First seen (parsed timestamp)": alert.get("first_seen"),
                "Why related": "Shares source IP " + ", ".join(shared_sources),
            }
        )
    return rows


def _top_sources_chart(risks: dict[str, dict[str, Any]]) -> alt.Chart | None:
    """Build a ranked source-risk chart from the analyzer's actual risk results."""
    values = [
        {"source_ip": ip, "score": value["score"], "band": value["band"]}
        for ip, value in sorted(risks.items(), key=lambda item: (-item[1]["score"], item[0]))[:8]
    ]
    if not values:
        return None
    chart = (
        alt.Chart(alt.Data(values=values))
        .mark_bar(cornerRadiusEnd=4, height=22)
        .encode(
            y=alt.Y(
                "source_ip:N",
                sort="-x",
                title=None,
                axis=alt.Axis(
                    labelLimit=320,
                    labelOverlap=False,
                    labelColor=THEME_COLORS["text_secondary"],
                ),
            ),
            x=alt.X(
                "score:Q",
                title="Risk score (0–100)",
                scale=alt.Scale(domain=[0, 100]),
                axis=alt.Axis(tickCount=6, grid=True),
            ),
            color=alt.Color(
                "band:N",
                title="Risk band",
                scale=alt.Scale(
                    domain=["Low", "Medium", "High", "Critical"],
                    range=[
                        RISK_CHART_COLORS["Low"],
                        RISK_CHART_COLORS["Medium"],
                        RISK_CHART_COLORS["High"],
                        RISK_CHART_COLORS["Critical"],
                    ],
                ),
                legend=None,
            ),
            tooltip=[
                alt.Tooltip("source_ip:N", title="Source IP"),
                alt.Tooltip("score:Q", title="Risk score", format=".0f"),
                alt.Tooltip("band:N", title="Risk band"),
            ],
        )
        .properties(height=max(180, 44 * len(values)), title="Highest-risk sources")
    )
    return _style_chart(chart)


def _severity_distribution_chart(alerts: list[dict[str, Any]]) -> alt.LayerChart | None:
    """Show the observed rule-alert severity proportions and their exact total."""
    counts = Counter(
        alert.get("base_severity", alert.get("severity"))
        for alert in alerts
        if alert.get("base_severity", alert.get("severity")) in RISK_CHART_COLORS
    )
    values = [
        {"severity": severity, "count": counts[severity]}
        for severity in ("Critical", "High", "Medium", "Low")
        if counts[severity]
    ]
    if not values:
        return None
    total = sum(counts.values())
    arcs = (
        alt.Chart(alt.Data(values=values))
        .transform_joinaggregate(total_alerts="sum(count)")
        .transform_calculate(share="datum.count / datum.total_alerts")
        .mark_arc(
            innerRadius=54,
            outerRadius=78,
            stroke=THEME_COLORS["panel"],
            strokeWidth=2,
        )
        .encode(
            theta=alt.Theta("count:Q", stack=True),
            color=alt.Color(
                "severity:N",
                title="Rule severity",
                sort=["Critical", "High", "Medium", "Low"],
                legend=alt.Legend(
                    values=[row["severity"] for row in values], columns=2, orient="bottom"
                ),
                scale=alt.Scale(
                    domain=["Low", "Medium", "High", "Critical"],
                    range=[
                        RISK_CHART_COLORS["Low"],
                        RISK_CHART_COLORS["Medium"],
                        RISK_CHART_COLORS["High"],
                        RISK_CHART_COLORS["Critical"],
                    ],
                ),
            ),
            tooltip=[
                alt.Tooltip("severity:N", title="Rule severity"),
                alt.Tooltip("count:Q", title="Alerts", format=","),
                alt.Tooltip("share:Q", title="Share", format=".1%"),
            ],
        )
    )
    total_label = (
        alt.Chart(alt.Data(values=[{"total": total}]))
        .mark_text(fontSize=21, fontWeight=700, color=THEME_COLORS["text"])
        .encode(text=alt.Text("total:Q", format=","))
    )
    center_label = alt.Chart(alt.Data(values=[{}])).mark_text(
        text="ALERTS",
        dy=18,
        fontSize=9,
        fontWeight=600,
        color=THEME_COLORS["text_muted"],
    )
    return _style_chart(
        (arcs + total_label + center_label).properties(
            height=195, title="Alert severity distribution"
        )
    )


def _parse_quality_chart(parse_stats: dict[str, Any]) -> alt.Chart | None:
    """Compare parser-provided counts for mutually exclusive input-line outcomes."""
    lines_read = parse_stats.get("lines_read", 0)
    if not lines_read:
        return None
    values = [
        {"outcome": label, "lines": count, "color": color}
        for label, count, color in (
            ("Parsed records", parse_stats.get("events_parsed", 0), THEME_COLORS["green"]),
            ("Ignored lines", parse_stats.get("lines_ignored", 0), THEME_COLORS["blue"]),
            ("Malformed lines", parse_stats.get("lines_malformed", 0), THEME_COLORS["critical"]),
        )
    ]
    chart = (
        alt.Chart(alt.Data(values=values))
        .mark_bar(cornerRadiusEnd=3, height=20)
        .encode(
            y=alt.Y(
                "outcome:N",
                sort=["Parsed records", "Ignored lines", "Malformed lines"],
                title=None,
                axis=alt.Axis(labelLimit=200),
            ),
            x=alt.X("lines:Q", title="Input lines", scale=alt.Scale(domainMin=0)),
            color=alt.Color("color:N", scale=None, legend=None),
            tooltip=[
                alt.Tooltip("outcome:N", title="Line outcome"),
                alt.Tooltip("lines:Q", title="Lines", format=","),
            ],
        )
        .properties(height=145, title="Input-line disposition")
    )
    return _style_chart(chart)


def _style_chart(chart: Any) -> Any:
    """Apply a shared high-contrast visual style to local Altair charts."""
    return (
        chart.configure(
            background=THEME_COLORS["panel"],
            font="Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
            title=alt.TitleConfig(
                color=THEME_COLORS["text"], fontSize=14, fontWeight=600, anchor="start"
            ),
            view=alt.ViewConfig(stroke=THEME_COLORS["border_subtle"]),
        )
        .configure_axis(
            labelColor=THEME_COLORS["text_secondary"],
            titleColor=THEME_COLORS["text"],
            domainColor=THEME_COLORS["border"],
            tickColor=THEME_COLORS["border"],
            gridColor=THEME_COLORS["border_subtle"],
            gridOpacity=0.85,
            labelFontSize=11,
            titleFontSize=12,
        )
        .configure_legend(
            orient="bottom",
            direction="horizontal",
            columns=4,
            labelColor=THEME_COLORS["text_secondary"],
            titleColor=THEME_COLORS["text"],
            labelFontSize=11,
            titleFontSize=12,
        )
    )


def render_dashboard_table(st: Any, data: Any, **kwargs: Any) -> Any:
    """Render a native sortable table using the dashboard's shared table defaults."""
    kwargs.setdefault("width", "stretch")
    kwargs.setdefault("hide_index", True)
    return st.dataframe(data, **kwargs)


def alert_detail_summary(alert: dict[str, Any]) -> dict[str, Any]:
    """Select existing alert evidence for the structured analyst detail panel."""
    risk_score = alert.get("source_risk_score", alert.get("risk_score"))
    risk_band = alert.get("source_risk_band", alert.get("risk_band"))
    risk = f"{risk_score}/100 · {risk_band}" if risk_score is not None else "Unavailable"
    return {
        "Rule": alert.get("rule", "Unknown rule"),
        "Rule-level severity": alert.get("base_severity", alert.get("severity", "Unknown")),
        "Source IP": alert.get("source_ip", "Unavailable"),
        "Source risk": risk,
        "Attempts": alert.get("attempt_count", "Unavailable"),
        "First seen (parsed timestamp)": alert.get("first_seen", "Unavailable"),
        "Last seen (parsed timestamp)": alert.get("last_seen", "Unavailable"),
        "Description": alert.get("description", "No description available."),
        "Targeted usernames": ", ".join(alert.get("usernames_targeted", [])) or "Not available",
        "Authentication methods": ", ".join(alert.get("authentication_methods", []))
        or "Not available",
        "MITRE ATT&CK": " · ".join(
            value
            for value in (alert.get("mitre_attack_id"), alert.get("mitre_technique_name"))
            if value
        )
        or "Not mapped",
        **(
            {"MITRE mapping note": alert["mitre_mapping_note"]}
            if alert.get("mitre_mapping_note")
            else {}
        ),
        "Recommended action": alert.get("recommended_action", "No recommended action available."),
    }


def _dashboard_theme_css() -> str:
    """Return the shared dark SOC visual system without remote assets."""
    return """<style>
    :root {
      --sentinel-background: #070b16;
      --sentinel-surface: #0b1120;
      --sentinel-panel: #10192b;
      --sentinel-panel-alt: #131f35;
      --sentinel-elevated: #17253d;
      --sentinel-border: #243651;
      --sentinel-border-subtle: #1c2b42;
      --sentinel-text: #edf4ff;
      --sentinel-secondary: #a7b7cc;
      --sentinel-muted: #7487a2;
      --sentinel-cyan: #36d7f5;
      --sentinel-teal: #35e0c1;
      --sentinel-blue: #548cff;
      --sentinel-violet: #9b7bff;
      --sentinel-magenta: #f06bd8;
      --sentinel-green: #40d9a2;
      --sentinel-amber: #ffc76a;
      --sentinel-orange: #ff925c;
      --sentinel-critical: #ff5d73;
    }
    .stApp, [data-testid="stAppViewContainer"] { background: var(--sentinel-background); color: var(--sentinel-text); font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    .block-container { max-width: 1680px; padding: .75rem 1.5rem 2.5rem; }
    [data-testid="stHeader"] { background: rgba(7, 11, 22, .92); }
    [data-testid="stSidebar"] { background: var(--sentinel-surface); border-right: 1px solid var(--sentinel-border-subtle); color: var(--sentinel-text); }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] [data-testid="stWidgetLabel"] p,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p { color: var(--sentinel-secondary); opacity: 1; }
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3, [data-testid="stSidebar"] strong { color: var(--sentinel-text); }
    nav[data-testid="stSidebarNav"] { padding: .45rem .55rem .8rem; border-bottom: 1px solid var(--sentinel-border-subtle); }
    nav[data-testid="stSidebarNav"] a { color: var(--sentinel-secondary); border-radius: 7px; min-height: 2.45rem; font-weight: 560; transition: background-color .12s ease, color .12s ease; }
    nav[data-testid="stSidebarNav"] a:hover { background: var(--sentinel-panel-alt); color: var(--sentinel-cyan); }
    nav[data-testid="stSidebarNav"] a[aria-current="page"] { background: var(--sentinel-elevated); color: var(--sentinel-cyan); font-weight: 700; box-shadow: inset 3px 0 var(--sentinel-cyan); }
    nav[data-testid="stSidebarNav"] a:focus-visible { outline: 2px solid var(--sentinel-cyan); }
    div[class*="st-key-sentinel-brand-header"] [data-testid="stHorizontalBlock"] { display: grid; grid-template-columns: 48px minmax(0, 1fr); align-items: center; gap: .65rem; }
    div[class*="st-key-sentinel-brand-header"] [data-testid="stColumn"] { width: auto; min-width: 0; }
    [data-testid="stSidebar"] [data-testid="stExpander"] { border: 1px solid var(--sentinel-border-subtle); border-radius: 7px; background: var(--sentinel-panel); }
    [data-testid="stSidebar"] [data-testid="stExpander"] summary { color: var(--sentinel-text); }
    [data-testid="stSidebar"] [data-baseweb="select"] > div,
    [data-testid="stSidebar"] input,
    [data-testid="stSidebar"] textarea { background: var(--sentinel-panel-alt); color: var(--sentinel-text); border-color: var(--sentinel-border); }
    [data-testid="stSidebar"] [data-testid="stFileUploader"] section { background: var(--sentinel-panel-alt); border-color: var(--sentinel-border); }
    [data-testid="stSidebar"] [data-testid="stButton"] button { background: var(--sentinel-panel-alt); color: var(--sentinel-text); border-color: var(--sentinel-border); }
    [data-testid="stSidebar"] [data-testid="stButton"] button:hover { background: var(--sentinel-elevated); border-color: var(--sentinel-cyan); color: var(--sentinel-text); }
    [data-testid="stMetric"] { min-height: 86px; padding: 12px 14px; background: var(--sentinel-panel); border: 1px solid var(--sentinel-border-subtle); border-left: 3px solid var(--sentinel-blue); border-radius: 7px; }
    [data-testid="stMetricLabel"] { color: var(--sentinel-secondary); font-size: .78rem; font-weight: 600; }
    [data-testid="stMetricValue"] { color: var(--sentinel-text); font-size: clamp(1.35rem, 1.8vw, 1.8rem); font-weight: 700; }
    div[class*="st-key-kpi-critical"] [data-testid="stMetric"] { border-left-color: var(--sentinel-critical); }
    div[class*="st-key-kpi-high"] [data-testid="stMetric"] { border-left-color: var(--sentinel-orange); }
    div[class*="st-key-kpi-medium"] [data-testid="stMetric"] { border-left-color: var(--sentinel-amber); }
    div[class*="st-key-kpi-low"] [data-testid="stMetric"] { border-left-color: var(--sentinel-cyan); }
    div[class*="st-key-kpi-good"] [data-testid="stMetric"] { border-left-color: var(--sentinel-green); }
    div[class*="st-key-kpi-info"] [data-testid="stMetric"] { border-left-color: var(--sentinel-blue); }
    [data-testid="stDataFrame"], [data-testid="stTable"] { border: 1px solid var(--sentinel-border); border-radius: 7px; overflow: hidden; background: var(--sentinel-panel); }
    [data-testid="stDataFrame"] { font-size: .82rem; }
    [data-testid="stAltairChart"] { padding: .3rem; background: var(--sentinel-panel); border: 1px solid var(--sentinel-border-subtle); border-radius: 7px; transition: border-color .12s ease; }
    [data-testid="stAltairChart"]:hover { border-color: var(--sentinel-border); }
    [data-testid="stVerticalBlockBorderWrapper"] { background: var(--sentinel-panel); border-color: var(--sentinel-border-subtle); border-radius: 7px; }
    [data-testid="stSubheader"] { color: var(--sentinel-text); font-weight: 650; letter-spacing: -.01em; }
    [data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p { color: var(--sentinel-secondary); opacity: 1; }
    [data-testid="stMain"] h1 { color: var(--sentinel-text); font-size: clamp(1.6rem, 2.2vw, 1.9rem); font-weight: 700; letter-spacing: -.02em; }
    [data-testid="stAlert"] { border-radius: 7px; }
    [data-testid="stButton"] button, [data-testid="stDownloadButton"] button { border-radius: 6px; font-weight: 600; min-height: 2.4rem; }
    :focus-visible { outline: 2px solid var(--sentinel-cyan); outline-offset: 2px; }
    @media (max-width: 768px) {
      .block-container { padding: 2.8rem .8rem 1.5rem; }
      [data-testid="stMetric"] { min-height: 76px; padding: 10px; }
      [data-testid="stMetricValue"] { font-size: 1.25rem; }
    }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; } }
    </style>"""


def _render_metric_grid(
    st: Any,
    metrics: list[tuple[str, str | int], ...] | list[tuple[str, str | int, str]],
    *,
    columns_per_row: int = 3,
) -> None:
    """Render compact metric cards in responsive-sized rows with semantic accent tones."""
    tones = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}
    normalized = []
    for item in metrics:
        label, value, *explicit_tone = item
        tone = explicit_tone[0] if explicit_tone else tones.get(label.split()[0], "info")
        normalized.append((label, value, tone))
    for row_start in range(0, len(normalized), columns_per_row):
        row = normalized[row_start : row_start + columns_per_row]
        columns = st.columns(columns_per_row)
        for index, (column, (label, value, tone)) in enumerate(zip(columns, row)):
            key_label = re.sub(r"[^a-z0-9]+", "-", label.casefold()).strip("-")
            with column.container(key=f"kpi-{tone}-{key_label}-{row_start + index}"):
                st.metric(label, value)


def _brand_asset_for_page(_page_name: str) -> Path:
    """Select the original compact sparkle mark for responsive Sentinel branding."""
    return PROJECT_DIR / "sentinel-sparkle.svg"


def _render_brand_header(st: Any, page_name: str) -> None:
    """Render a compact sparkle mark and contextual page heading."""
    display_name = PAGE_DISPLAY_NAMES.get(page_name, page_name)
    subtitle = PAGE_SUBTITLES.get(page_name, "Sentinel Log Analyser · Local analysis")
    with st.container(key="sentinel-brand-header"):
        icon, title = st.columns([0.08, 1], vertical_alignment="center", gap="small")
        icon.image(str(_brand_asset_for_page(page_name)), width=40)
        title.title(display_name)
        title.caption(subtitle)


def _root_and_username_summary(
    events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Count targeted usernames and root outcomes from parsed authentication events."""
    usernames: Counter[str] = Counter()
    root = Counter()
    for event in events:
        if event.get("event_type") not in {"authentication_failure", "authentication_success"}:
            continue
        weight = event_occurrences(event)
        username = event.get("username")
        if username and event.get("event_type") == "authentication_failure":
            usernames[username] += weight
        if username == "root":
            if event.get("event_type") == "authentication_failure":
                root["failed"] += weight
            else:
                root["successful"] += weight
    return (
        [{"Username": name, "Failed attempts": count} for name, count in usernames.most_common(10)],
        {"failed": root["failed"], "successful": root["successful"]},
    )


def source_investigation_summary(events: list[dict[str, Any]], selected_ip: str) -> dict[str, Any]:
    """Build a source-only investigation summary from directly attributable events."""
    source_events = [event for event in events if event.get("source_ip") == selected_ip]
    username_rows, root_counts = _root_and_username_summary(source_events)
    _, failures, _, successes = source_outcome_counts(source_events, log_type="ssh")
    methods = sorted(
        {
            str(event["authentication_method"])
            for event in source_events
            if event.get("event_type") in {"authentication_failure", "authentication_success"}
            and event.get("authentication_method")
        }
    )
    return {
        "events": source_events,
        "username_rows": username_rows,
        "root_counts": root_counts,
        "failed_attempts": failures,
        "successful_logins": successes,
        "authentication_methods": methods,
    }


def incident_evidence_events(
    events: list[dict[str, Any]], incident: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return only event records explicitly contributing to a correlated incident."""
    evidence_ids = set(incident.get("evidence_event_ids", []))
    return [event for event in events if event.get("_event_id", id(event)) in evidence_ids]


def _dashboard_page_context(
    events: list[dict[str, Any]],
    parse_stats: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    """Build one shared, filtered-data context for all SOC dashboard pages."""
    visible_events, visible_result = filter_dashboard_data(
        events, result, severities=set(SEVERITIES)
    )
    return {
        "events": visible_events,
        "parse_stats": parse_stats,
        "result": visible_result,
        "alerts": visible_result["alerts"],
        "incidents": visible_result["incidents"],
        "risks": visible_result["risk_scores"],
        "metrics": summarize_dashboard_metrics(
            visible_result["alerts"], visible_result["risk_scores"], visible_result["incidents"]
        ),
    }


def _render_soc_page(st: Any, page_name: str, context: dict[str, Any]) -> None:
    """Render a focused SOC page using the shared analysis result."""
    events = context["events"]
    alerts = context["alerts"]
    incidents = context["incidents"]
    risks = context["risks"]
    parse_stats = context["parse_stats"]
    _render_brand_header(st, page_name)
    if context.get("active_filters"):
        st.caption("Active filters · " + " · ".join(context["active_filters"]))

    if page_name == "Overview":
        metrics = context["metrics"]
        _render_metric_grid(
            st,
            (
                ("Critical alerts", metrics["critical_alerts"], "critical"),
                ("High alerts", metrics["high_alerts"], "high"),
                ("Medium alerts", metrics["medium_alerts"], "medium"),
                ("Low alerts", metrics["low_alerts"], "low"),
                ("Critical-risk IPs", metrics["critical_risk_sources"], "critical"),
                ("Incidents", metrics["incidents"], "info"),
            ),
            columns_per_row=6,
        )
        with st.container(border=True):
            context_columns = st.columns(3)
            context_columns[0].caption("LOG TYPE")
            context_columns[0].write(context.get("log_type", "SSH"))
            context_columns[1].caption("INPUT")
            context_columns[1].write(context.get("input_label", "Selected local log"))
            context_columns[2].caption("ANALYSIS STATUS")
            context_columns[2].write("Complete · analyzed locally")
        lines = parse_stats.get("lines_read", 0)
        malformed = parse_stats.get("lines_malformed", 0)
        malformed_rate = 100 * malformed / lines if lines else 0.0
        st.caption(
            f"Parsed records: {parse_stats.get('events_parsed', 0)} · "
            f"Malformed lines: {malformed} / {lines} ({malformed_rate:.1f}%)"
        )
        st.caption(
            "Alert severity and source risk are separate measures. Timestamp interpretation is shown in Settings and exports."
        )
        attempts_chart = _overview_attempts_chart(events)
        if attempts_chart is not None:
            st.altair_chart(attempts_chart, width="stretch")
        else:
            st.info("No timestamped failed activity is available in this scope.")
        left_chart, right_chart = st.columns([1.4, 1], gap="large")
        source_chart = _top_sources_chart(risks)
        with left_chart:
            if source_chart is not None:
                st.caption(
                    "Source risk · Top 8 ranked by existing score. All sources remain on Sources. "
                    "Color represents risk band; hover for score and band."
                )
                st.altair_chart(source_chart, width="stretch")
            else:
                st.info("No source risk scores are available in this scope.")
        with right_chart:
            severity_chart = _severity_distribution_chart(alerts)
            if severity_chart is not None:
                st.altair_chart(severity_chart, width="stretch")
            else:
                st.caption("No alerts are available for a severity distribution.")
        auth_failures = parse_stats.get("authentication_failures")
        auth_successes = parse_stats.get("authentication_successes")
        if auth_failures is not None and auth_successes is not None:
            st.subheader("Authentication outcomes")
            _render_metric_grid(
                st,
                (
                    ("Failed authentications", auth_failures, "high"),
                    ("Successful authentications", auth_successes, "good"),
                    (
                        "Failed root authentications",
                        parse_stats.get("root_authentication_failures", 0),
                        "critical",
                    ),
                    (
                        "Successful root authentications",
                        parse_stats.get("root_authentication_successes", 0),
                        "good",
                    ),
                ),
            )
        success_alerts = [
            alert
            for alert in alerts
            if alert.get("rule") in {"ssh_success_after_failures", "web_success_after_failures"}
        ]
        if success_alerts:
            st.warning(
                "Potential compromise indicator: successful authentication followed repeated "
                "failures. This evidence does not confirm compromise."
            )
    elif page_name == "Alerts":
        rows = []
        for alert in alerts:
            base_severity = alert.get("base_severity", alert.get("severity"))
            source_risk = risks.get(alert.get("source_ip"), {})
            row = {
                "Severity": f"{_severity_symbol(base_severity)} {base_severity}",
                "Rule": alert.get("rule"),
                "Source IP": alert.get("source_ip"),
                "First seen (parsed timestamp)": alert.get("first_seen"),
                "Last seen (parsed timestamp)": alert.get("last_seen"),
                "Attempts": alert.get("attempt_count"),
                "Source risk": (
                    f"{source_risk.get('score')}/100 · {_risk_band_symbol(source_risk.get('band'))} {source_risk.get('band')}"
                    if source_risk
                    else "Unavailable"
                ),
                "Usernames": ", ".join(alert.get("usernames_targeted", [])),
            }
            rows.append(row)
        render_dashboard_table(
            st,
            rows,
            width="stretch",
            hide_index=True,
            column_config={
                "Severity": st.column_config.TextColumn(
                    "Severity", help="Original rule-level severity."
                ),
                "Attempts": st.column_config.NumberColumn("Attempts", format="%d"),
                "Source IP": st.column_config.TextColumn("Source IP", width="small"),
                "Rule": st.column_config.TextColumn("Detection rule", width="medium"),
            },
        )
        if rows:
            selected = st.selectbox(
                "Alert details", range(len(rows)), format_func=lambda i: rows[i]["Rule"]
            )
            selected_alert = alerts[selected]
            detail = alert_detail_summary(selected_alert)
            st.subheader(detail["Rule"])
            st.caption(
                "Rule-level severity is distinct from the source's composite risk score and band."
            )
            detail_columns = st.columns(4)
            severity = detail["Rule-level severity"]
            detail_columns[0].badge(
                f"{_severity_symbol(severity)} {severity}",
                color=RISK_COLORS.get(severity, "gray"),
            )
            detail_columns[1].metric("Attempts", detail["Attempts"])
            detail_columns[2].metric("Source IP", detail["Source IP"])
            detail_columns[3].metric("Source risk", detail["Source risk"])
            time_columns = st.columns(2)
            time_columns[0].markdown("**First seen (parsed timestamp)**")
            time_columns[0].write(detail["First seen (parsed timestamp)"])
            time_columns[1].markdown("**Last seen (parsed timestamp)**")
            time_columns[1].write(detail["Last seen (parsed timestamp)"])
            st.markdown("**What was observed**")
            st.write(detail["Description"])
            st.markdown("**Targeted usernames**")
            st.write(detail["Targeted usernames"])
            st.markdown("**Authentication methods**")
            st.write(detail["Authentication methods"])
            st.markdown("**MITRE ATT&CK**")
            st.write(detail["MITRE ATT&CK"])
            st.info(detail["Recommended action"])
            if selected_alert.get("session_activity"):
                st.write("Matching SSH session context", selected_alert["session_activity"])
            with st.expander("Raw JSON evidence", expanded=False):
                st.json(_output_value(selected_alert))
            related_rows = related_activity_rows(alerts, selected_alert)
            if related_rows:
                st.subheader("Related activity")
                st.caption(
                    "Advisory links based only on a shared source IP; alerts remain separate "
                    "and no similarity score is inferred."
                )
                render_dashboard_table(st, related_rows)
        else:
            st.info("No alerts match the current filters.")
    elif page_name == "Incidents":
        rows = [
            {
                "Incident ID": item["incident_id"],
                "Severity": f"{_severity_symbol(item['combined_severity'])} {item['combined_severity']}",
                "Source IP": item["source_ip"],
                "Source risk": f"{item.get('risk_score', 'n/a')}/100 · {_risk_band_symbol(item.get('risk_band'))} {item.get('risk_band', 'Unavailable')}",
                "First seen (parsed timestamp)": item["first_seen"],
                "Last seen (parsed timestamp)": item["last_seen"],
                "Rules": ", ".join(item["contributing_rules"]),
                "Evidence events": item.get("attempt_count", "n/a"),
            }
            for item in incidents
        ]
        render_dashboard_table(
            st,
            rows,
            width="stretch",
            hide_index=True,
            column_config={
                "Severity": st.column_config.TextColumn(
                    "Severity", help="Composite incident severity."
                ),
                "Evidence events": st.column_config.NumberColumn("Evidence events", format="%d"),
            },
        )
        if incidents:
            selected_id = st.selectbox(
                "Incident detail", [item["incident_id"] for item in incidents]
            )
            incident = next(item for item in incidents if item["incident_id"] == selected_id)
            with st.expander("Incident evidence and context", expanded=True):
                st.write(incident["summary"])
                st.write("Contributing rule IDs", incident.get("contributing_rules", []))
                st.write("Targeted usernames", incident.get("usernames_targeted", []))
                st.write("Authentication methods", incident.get("authentication_methods", []))
                st.write("SSH session context", incident.get("session_activity", []))
                st.write(
                    "Supporting authentication context", incident.get("supporting_evidence", [])
                )
            st.caption(
                f"{incident.get('attempt_count', 'n/a')} deduplicated weighted evidence events · "
                f"{incident.get('combined_severity')} composite severity · "
                f"source risk {incident.get('risk_score', 'n/a')}/100 "
                f"{incident.get('risk_band', '')}"
            )
            if incident.get("session_activity"):
                st.write("Linked SSH session-open evidence", incident["session_activity"])
            first = _as_datetime(incident.get("first_seen"))
            last = _as_datetime(incident.get("last_seen"))
            contributing_alerts = [
                alert
                for alert in alerts
                if alert.get("source_ip") == incident.get("source_ip")
                and alert.get("rule") in set(incident.get("contributing_rules", []))
                and (alert_first := _as_datetime(alert.get("first_seen"))) is not None
                and (alert_last := _as_datetime(alert.get("last_seen"))) is not None
                and first is not None
                and last is not None
                and alert_first <= last
                and alert_last >= first
            ]
            st.subheader("Contributing alerts")
            render_dashboard_table(
                st,
                [
                    {
                        "Rule": alert.get("rule"),
                        "Severity": alert.get("base_severity", alert.get("severity")),
                        "Attempts": alert.get("attempt_count"),
                        "First seen (parsed timestamp)": alert.get("first_seen"),
                        "Last seen (parsed timestamp)": alert.get("last_seen"),
                        "Evidence": alert.get("description"),
                        "Recommended action": alert.get("recommended_action"),
                    }
                    for alert in contributing_alerts
                ],
                width="stretch",
                hide_index=True,
            )
            if not contributing_alerts:
                st.info("No contributing alert details are available in the current filter scope.")
            timeline = [
                {
                    "Timestamp (parsed timestamp)": _as_datetime(event.get("timestamp")),
                    "Event": event.get("event_type", "web_request"),
                    "Username": event.get("username"),
                    "Method": event.get("authentication_method"),
                    "Status": event.get("status"),
                    "Path": event.get("path"),
                }
                for event in incident_evidence_events(events, incident)
            ]
            st.subheader("Supporting event timeline")
            render_dashboard_table(st, timeline, width="stretch", hide_index=True)
        else:
            st.info("No correlated incidents are present in this view.")
    elif page_name == "Sources":
        source_log_type = "ssh" if "authentication_failures" in parse_stats else "web"
        source_rows = source_risk_rows(risks, events, alerts, incidents, log_type=source_log_type)
        source_chart = _top_sources_chart(risks)
        if source_chart is not None:
            st.caption("Top 8 by existing risk score; the table below retains every source.")
            st.altair_chart(source_chart, width="stretch")
        if source_rows:
            render_dashboard_table(
                st,
                source_rows,
                width="stretch",
                hide_index=True,
                column_config={
                    "Risk score": st.column_config.NumberColumn("Risk score / 100", format="%d"),
                    "Risk band": st.column_config.TextColumn(
                        "Risk band", help="Label accompanies the numeric score."
                    ),
                },
            )
        else:
            st.info("No sources are available in the current filter scope.")
        if risks:
            selected_ip = st.selectbox(
                "Investigate source IP", list(risks), key="source_investigation"
            )
            source_summary = source_investigation_summary(events, selected_ip)
            source_events = source_summary["events"]
            source_alerts = [
                alert
                for alert in alerts
                if alert.get("source_ip") == selected_ip
                or selected_ip in alert.get("source_ips", [])
            ]
            source_incidents = [
                incident for incident in incidents if incident.get("source_ip") == selected_ip
            ]
            stamps = [
                stamp
                for event in source_events
                if (stamp := _as_datetime(event.get("timestamp"))) is not None
            ]
            failure_label, failures, success_label, successes = source_outcome_counts(
                source_events, log_type=source_log_type
            )
            st.subheader(f"Source investigation: {selected_ip}")
            risk_summary = st.columns([1, 2])
            risk_summary[0].metric("Risk score", f"{risks[selected_ip]['score']}/100")
            risk_summary[1].caption("Risk band")
            band = risk_band_badge(risks[selected_ip]["band"])
            risk_summary[1].badge(band["label"], color=band["color"])
            explanation = context["result"].get("risk_explanations", {}).get(selected_ip)
            if explanation:
                st.subheader("Source-risk score explanation")
                factor_rows = [
                    {
                        "Factor": name.replace("_", " ").title(),
                        "Evidence": str(factor["evidence"]),
                        "Contribution": factor["contribution"],
                        "Policy": factor["policy"],
                    }
                    for name, factor in explanation["factors"].items()
                ]
                factor_rows.append(
                    {
                        "Factor": "Policy adjustment",
                        "Evidence": "Configured floor/cap policy",
                        "Contribution": explanation["policy_adjustment"]["contribution"],
                        "Policy": explanation["policy_adjustment"]["policy"],
                    }
                )
                render_dashboard_table(st, factor_rows, width="stretch", hide_index=True)
                st.caption(explanation["confidence"]["rationale"])
                st.caption(f"Uncertainty: {explanation['uncertainty']}")
            _render_metric_grid(
                st,
                (
                    (failure_label, failures, "high"),
                    (success_label, successes, "good"),
                    ("Alerts", len(source_alerts), "info"),
                    ("Incidents", len(source_incidents), "info"),
                ),
                columns_per_row=4,
            )
            if stamps:
                st.caption(
                    f"Observed between {min(stamps)} and {max(stamps)} in the parsed timestamp basis."
                )
            if source_log_type == "ssh":
                st.subheader("Source-attributed authentication")
                render_dashboard_table(
                    st, source_summary["username_rows"], width="stretch", hide_index=True
                )
                st.write(
                    f"Root authentication outcomes for {selected_ip}: "
                    f"{source_summary['root_counts']['failed']} failed · "
                    f"{source_summary['root_counts']['successful']} successful"
                )
                st.write(
                    "Authentication methods directly present in this source's events: "
                    + (", ".join(source_summary["authentication_methods"]) or "Not available")
                )
            st.write(
                "Contributing rules: "
                + (", ".join(sorted({alert["rule"] for alert in source_alerts})) or "None")
            )
            linked_context = [
                session
                for alert in source_alerts
                if alert.get("source_ip") == selected_ip
                for session in alert.get("session_activity", [])
            ]
            if linked_context:
                st.write("Linked session context", linked_context)
            st.subheader("Source activity")
            render_dashboard_table(
                st, timeline_event_rows(source_events), width="stretch", hide_index=True
            )
            if source_incidents:
                st.write(
                    "Related incidents", [incident["incident_id"] for incident in source_incidents]
                )
    elif page_name == "Successful Logins":
        st.caption(
            "Successful authentication observed; this alone is not proof of malicious activity or compromise. "
            "Session IDs are absent from the supported format. Any displayed duration is an estimate based on a unique host/PID/username lifecycle match."
        )
        login_rows = context["result"].get("successful_logins", [])
        if login_rows:
            display_rows = []
            for row in login_rows:
                duration = row.get("duration_seconds")
                duration_text = (
                    f"{duration // 60}m {duration % 60}s" if duration is not None else "Unavailable"
                )
                related_failures = row.get("related_failures")
                display_rows.append(
                    {
                        "Finding": row.get("classification", "Successful authentication observed"),
                        "Timestamp (parsed timestamp)": row.get("timestamp"),
                        "Source IP": row.get("source_ip") or "Unavailable",
                        "Username": row.get("username") or "Unavailable",
                        "Host": row.get("hostname") or "Unavailable",
                        "sshd PID": row.get("process_id")
                        if row.get("process_id") is not None
                        else "Unavailable",
                        "Session ID": "Unavailable in log",
                        "Duration": duration_text,
                        "Related failures": related_failures
                        if related_failures is not None
                        else "Unavailable",
                        "Related alerts": ", ".join(row.get("related_alert_rules", [])) or "None",
                        "Linkage": row.get("correlation_status"),
                        "Data-quality limits": "; ".join(row.get("data_quality_limitations", [])),
                    }
                )
            render_dashboard_table(st, display_rows, width="stretch", hide_index=True)
            st.caption(
                f"{len(login_rows):,} successful authentication record(s) in this filter scope."
            )
        else:
            st.info("No successful SSH authentications are available in the current filter scope.")
    elif page_name == "Timeline":
        st.caption(
            "Events use the parsed timestamp basis described in Settings. "
            "Session lifecycle records without a source are labeled as unlinked context."
        )
        chart = _timeline_chart(events)
        if chart is None:
            st.info("No timestamped failed events are available in the current scope.")
            timeline_events = events
        else:
            generation = st.session_state.get("timeline_brush_generation", 0)
            selection = st.altair_chart(
                chart,
                key=f"timeline_brush_chart_{generation}",
                on_select="rerun",
                selection_mode="timeline_brush",
            )
            bounds = timeline_selection_bounds(selection.selection)
            if bounds:
                start, end = bounds
                st.caption(
                    f"Brushed parsed-time interval: {start.isoformat()}–{end.isoformat()}; "
                    "clear the interval to restore all events."
                )
                if st.button("Clear time selection", key="clear_timeline_selection"):
                    st.session_state["timeline_brush_generation"] = generation + 1
                    st.rerun()
            timeline_events = filter_timeline_events(events, bounds)
        timeline_rows = timeline_event_rows(timeline_events)
        st.subheader(f"Chronological events ({len(timeline_rows):,})")
        if timeline_rows:
            display_limit = 500
            render_dashboard_table(
                st, timeline_rows[-display_limit:][::-1], width="stretch", hide_index=True
            )
            if len(timeline_rows) > display_limit:
                st.caption(
                    f"Showing the newest {display_limit:,} rows; the analysis still retains "
                    f"{len(timeline_rows):,} timestamped events in this scope."
                )
        else:
            st.info("No timestamped events are available in the current filter scope.")
    elif page_name == "Detection Coverage":
        st.caption(
            "Rule descriptions and known limitations come from the maintained detection inventory. "
            "Synthetic tests do not establish real-world accuracy."
        )
        inventory_path = PROJECT_DIR / "docs" / "detection-inventory.md"
        if inventory_path.is_file():
            inventory = inventory_path.read_text(encoding="utf-8")
            rule_rows = detection_inventory_rows(inventory)
            if not rule_rows:
                st.warning("No detection rules were found in the maintained inventory.")
            else:
                render_dashboard_table(
                    st,
                    [
                        {
                            **row,
                            "Base severity": f"{_severity_symbol(row['Base severity'])} {row['Base severity']}",
                        }
                        for row in detection_summary_rows(rule_rows)
                    ],
                    width="stretch",
                    height=min(390, 42 * (min(len(rule_rows), 8) + 1)),
                    hide_index=True,
                    column_config={
                        "Detection": st.column_config.TextColumn("Detection", width="large"),
                        "Rule ID": st.column_config.TextColumn("Rule ID", width="medium"),
                        "Base severity": st.column_config.TextColumn(
                            "Rule severity",
                            help="Rule severity; incident and source risk are separate.",
                        ),
                    },
                )
                for row in rule_rows:
                    with st.expander(f"{row['Detection']} · {row['Rule']}"):
                        detail_columns = st.columns(2)
                        detail_columns[0].markdown("**Severity behavior**")
                        detail_columns[0].write(row["Severity"])
                        detail_columns[0].markdown("**Threshold and window**")
                        detail_columns[0].write(row["Threshold/window"])
                        detail_columns[0].markdown("**MITRE ATT&CK**")
                        detail_columns[0].write(row["MITRE ATT&CK"] or "Not mapped")
                        detail_columns[1].markdown("**Required evidence**")
                        detail_columns[1].write(row["Required evidence"])
                        detail_columns[1].markdown("**Known limitations**")
                        detail_columns[1].write(row["Known limitations"])
                        st.caption(row["Validation status"])
                        with st.expander("Developer traceability"):
                            st.code(row["Test references"] or "No test reference is documented.")
        else:
            st.error("The detection inventory document is unavailable in this installation.")
    elif page_name == "Data Quality":
        log_type = context.get("log_type", "SSH").casefold()
        sections = data_quality_sections(parse_stats, events, log_type=log_type)
        lines = parse_stats.get("lines_read", 0)
        malformed = parse_stats.get("lines_malformed", 0)
        for section_name, metrics in sections:
            st.subheader(section_name)
            if section_name == "Parser health":
                health = dict(metrics)
                health_columns = st.columns([1, 2])
                health_columns[0].metric("Malformed percentage", health["Malformed percentage"])
                health_columns[1].markdown("**Supported format**")
                health_columns[1].write(health["Supported format"])
                health_columns[1].markdown("**Malformed reasons**")
                health_columns[1].write(health["Malformed reasons"])
                continue
            _render_metric_grid(
                st,
                [
                    (
                        label,
                        value,
                        "high"
                        if label in {"Malformed lines", "Malformed percentage"}
                        and value not in {0, "0.0%"}
                        else "good"
                        if label == "Ignored lines"
                        else "info",
                    )
                    for label, value in metrics
                ],
                columns_per_row=2 if section_name == "Authentication attempts" else 4,
            )
        quality_chart = _parse_quality_chart(parse_stats)
        if quality_chart is not None:
            st.altair_chart(quality_chart, width="stretch")
        if lines and 100 * malformed / lines > 5:
            st.warning("Malformed records exceed 5% of input lines.")
        reason_rows = malformed_summary_rows(parse_stats)
        with st.expander("Malformed line reasons", expanded=bool(reason_rows)):
            if reason_rows:
                render_dashboard_table(st, reason_rows, width="stretch", hide_index=True)
            else:
                st.caption("No malformed lines were recorded.")
        if parse_stats.get("malformed_records"):
            with st.expander("Sample malformed line locations"):
                render_dashboard_table(
                    st, parse_stats["malformed_records"], width="stretch", hide_index=True
                )
                if parse_stats.get("malformed_records_truncated"):
                    st.caption(
                        f"{parse_stats['malformed_records_truncated']} further samples were omitted."
                    )
    elif page_name == "Reports":
        st.caption(
            "Downloads use the shared, filtered analysis result. HTML escapes log-derived values and embeds its assets."
        )
        payload = json.dumps(_output_value(context["result"]), indent=2, ensure_ascii=False)
        csv_payload = render_csv(alerts, context["result"].get("timestamp_interpretation"))
        from html_report import render_html_report
        from markdown_report import render_markdown_report

        html_payload = render_html_report(events, context["result"])
        markdown_payload = render_markdown_report(context["result"])
        login_csv_payload = render_successful_logins_csv(
            context["result"].get("successful_logins", [])
        )
        columns = st.columns(5)
        columns[0].download_button("Download JSON", payload, "alerts.json", "application/json")
        columns[1].download_button("Download CSV", csv_payload, "alerts.csv", "text/csv")
        columns[2].download_button(
            "Download successful logins CSV", login_csv_payload, "successful_logins.csv", "text/csv"
        )
        columns[3].download_button("Download HTML", html_payload, "report.html", "text/html")
        columns[4].download_button(
            "Download Markdown", markdown_payload, "incident-report.md", "text/markdown"
        )
    elif page_name == "Settings":
        st.caption(
            "Values below are the validated settings used for this analysis. Sidebar threshold, "
            "window, and allowlist controls apply to this session and do not update config.yaml."
        )
        config_used = context["result"].get("config_used", {})
        st.markdown("#### Input and timestamp settings")
        st.caption(
            context["result"]
            .get("timestamp_interpretation", {})
            .get("timezone_assumption", "Timezone interpretation unavailable.")
        )
        st.caption(
            context["result"].get("timestamp_interpretation", {}).get("offset_timestamp_policy", "")
        )
        render_dashboard_table(
            st,
            [
                {"Setting": "Log type", "Configured value": str(context.get("log_type", "SSH"))},
                {
                    "Setting": "Year / timestamp interpretation",
                    "Configured value": str(context.get("year", "Not applicable")),
                },
                {
                    "Setting": "Session allowlist",
                    "Configured value": "Provided"
                    if context.get("allowlist_enabled")
                    else "Not provided",
                },
            ],
            width="stretch",
            hide_index=True,
        )
        for index in range(0, len(groups := settings_sections(config_used)), 2):
            setting_columns = st.columns(2)
            for column, (section_name, values) in zip(setting_columns, groups[index : index + 2]):
                with column.expander(
                    section_name,
                    expanded=False,
                    icon=SETTING_ICONS.get(section_name, "⚙️"),
                ):
                    render_dashboard_table(
                        st,
                        settings_value_rows(values),
                        width="stretch",
                        hide_index=True,
                        height=min(210, 38 * (len(values) + 1)),
                    )
        with st.expander("Advanced: raw validated configuration"):
            st.json(_output_value(config_used))


def _show_soc_navigation(
    st: Any,
    path: Path,
    log_type: str,
    year: int,
    config: dict[str, Any],
    allowlist_text: str,
    threshold: int,
    window_seconds: int,
    input_source: str = "Sample log",
) -> None:
    """Analyze once and route shared results through native Streamlit pages."""
    try:
        events, parse_stats, result = analyze_for_dashboard(
            path,
            log_type=log_type,
            year=year,
            config=config,
            allowlist_text=allowlist_text,
            threshold=threshold,
            window_seconds=window_seconds,
        )
    except (OSError, ValueError) as error:
        st.error(f"Unable to analyze log: {error}")
        return

    def reset_if_options_changed(key: str, options: list[str]) -> None:
        """Reset a data-dependent filter when its available choices change."""
        signature_key = f"_{key}_options_signature"
        signature = tuple(options)
        if key not in st.session_state or st.session_state.get(signature_key) != signature:
            st.session_state[key] = list(options)
            st.session_state[signature_key] = signature

    with st.sidebar:
        all_sources = list(result["risk_scores"])
        st.markdown("#### Analysis filters")
        all_rules = sorted({alert.get("rule") for alert in result["alerts"] if alert.get("rule")})
        all_usernames = sorted(
            {
                username
                for alert in result["alerts"]
                for username in alert.get("usernames_targeted", [])
                if username
            }
        )
        reset_if_options_changed("global_rules", all_rules)
        reset_if_options_changed("global_usernames", all_usernames)
        if st.button("Clear all filters", key="clear_global_filters", use_container_width=True):
            for key in (
                "global_source_ip",
                "global_date_range",
                "global_severity",
                "global_rules",
                "global_usernames",
                "global_alert_search",
            ):
                st.session_state.pop(key, None)
            st.rerun()
        with st.expander("Event scope", expanded=True):
            selected_source = st.selectbox(
                "Source IP", ["All sources", *all_sources], key="global_source_ip"
            )
            date_selection = st.date_input(
                "Date range (parsed timestamp)", value=(), key="global_date_range"
            )
        start_date = end_date = None
        if isinstance(date_selection, tuple) and len(date_selection) == 2:
            start_date, end_date = date_selection
        elif isinstance(date_selection, date):
            start_date = end_date = date_selection
        with st.expander("Alert scope", expanded=False):
            severity_selection = st.multiselect(
                "Rule severity", SEVERITIES, default=list(SEVERITIES), key="global_severity"
            )
            selected_rules = st.multiselect("Detection rule", all_rules, key="global_rules")
            selected_usernames = st.multiselect(
                "Targeted username", all_usernames, key="global_usernames"
            )
            alert_search = st.text_input("Search alert details", key="global_alert_search")
        st.caption(
            "Source and parsed-time date filters scope events. Severity, rule, username, and text filter alerts, "
            "incidents, and report downloads."
        )
    selected_rules_set = None if selected_rules == all_rules else set(selected_rules)
    selected_usernames_set = (
        None if selected_usernames == all_usernames else set(selected_usernames)
    )
    visible_events, visible_result = filter_dashboard_data(
        events,
        result,
        source_ip=None if selected_source == "All sources" else selected_source,
        start_date=start_date,
        end_date=end_date,
        severities=set(severity_selection),
        rules=selected_rules_set,
        usernames=selected_usernames_set,
        search_query=alert_search,
    )
    context = _dashboard_page_context(visible_events, parse_stats, visible_result)
    active_filters = []
    if selected_source != "All sources":
        active_filters.append(f"Source {selected_source}")
    if start_date or end_date:
        active_filters.append(
            f"Parsed timestamp dates {start_date.isoformat() if start_date else 'any'}–"
            f"{end_date.isoformat() if end_date else 'any'}"
        )
    if set(severity_selection) != set(SEVERITIES):
        active_filters.append("Severity " + (", ".join(severity_selection) or "none"))
    if selected_rules_set is not None:
        active_filters.append(f"Rules {len(selected_rules_set)}/{len(all_rules)}")
    if selected_usernames_set is not None:
        active_filters.append(f"Usernames {len(selected_usernames_set)}/{len(all_usernames)}")
    if alert_search.strip():
        active_filters.append("Search applied")
    context.update(
        {
            "log_type": log_type.upper(),
            "input_label": f"{input_source}: {path.name}",
            "year": year
            if log_type == "ssh"
            else "Not applicable; web timestamps include timezones",
            "allowlist_enabled": bool(allowlist_text.strip()),
            "active_filters": active_filters,
        }
    )
    page_icons = {
        "Overview": "🏠",
        "Alerts": "🚨",
        "Incidents": "🛡️",
        "Sources": "🌐",
        "Timeline": "🕒",
        "Successful Logins": "✅",
        "Detection Coverage": "✅",
        "Data Quality": "📊",
        "Reports": "📄",
        "Settings": "⚙️",
    }
    pages = [
        st.Page(
            lambda page_title=title: _render_soc_page(st, page_title, context),
            title=title,
            url_path=title.casefold().replace(" ", "-"),
            icon=page_icons[title],
            default=title == "Overview",
        )
        for title in (
            "Overview",
            "Alerts",
            "Incidents",
            "Sources",
            "Timeline",
            "Successful Logins",
            "Detection Coverage",
            "Data Quality",
            "Reports",
            "Settings",
        )
    ]
    pages.append(
        st.Page(
            lambda: _show_analysis(
                st,
                path,
                log_type,
                year,
                config,
                allowlist_text,
                threshold,
                window_seconds,
                preloaded=(visible_events, parse_stats, visible_result),
            ),
            title="Detailed Analysis",
            url_path="detailed-analysis",
            icon="🔎",
        )
    )
    st.navigation({"SOC Dashboard": pages}, position="sidebar").run()


def _render_dashboard(st: Any) -> None:
    """Render the local-only Streamlit user interface."""
    st.set_page_config(
        page_title="Sentinel Log Analyser",
        page_icon=str(_brand_asset_for_page("Overview")),
        layout="wide",
    )
    selected_path: Path | None = None
    upload = None
    config = load_config(PROJECT_DIR / "config.yaml")
    with st.sidebar:
        brand_icon, brand_name = st.columns([0.2, 1], vertical_alignment="center")
        brand_icon.image(str(_brand_asset_for_page("Alerts")), width=32)
        brand_name.markdown("**Sentinel Log Analyser**")
        brand_name.caption("LOCAL LOG ANALYSIS")
        st.divider()
        with st.expander("Analysis input", expanded=True):
            log_type = st.selectbox("Log type", ("ssh", "web"), format_func=str.upper)
            source = st.radio("Input", ("Sample log", "Upload a log file"))
            if source == "Sample log":
                sample_name = "SSH sample" if log_type == "ssh" else "Web sample"
                selected_path = SAMPLE_LOGS[sample_name]
                st.caption(f"Selected sample · {selected_path.name}")
            else:
                upload = st.file_uploader("Choose a local log file", type=("log", "txt"))
                if upload is not None:
                    st.caption(f"Selected upload · {Path(upload.name).name}")
    if log_type == "ssh":
        default_threshold = config["brute_force"]["threshold"]
    else:
        default_threshold = config["web"]["login_threshold"]
    with st.sidebar:
        with st.expander("Detection settings", expanded=False):
            year = st.number_input(
                "Year for SSH syslog timestamps", 1970, 2200, datetime.now().year
            )
            threshold_label = (
                "Brute-force threshold (failures)"
                if log_type == "ssh"
                else "Web login and scanning threshold (requests)"
            )
            threshold_help = (
                "Minimum failed authentication events from one source in the configured window."
                if log_type == "ssh"
                else "Minimum matching login failures or 404 requests from one source in the configured window."
            )
            threshold = st.slider(threshold_label, 1, 50, default_threshold, help=threshold_help)
            window_seconds = st.slider(
                "Detection window (seconds)",
                1,
                3600,
                60,
                help="Time window used by the threshold-controlled detections.",
            )
            allowlist_text = st.text_area(
                "Optional trusted IP/CIDR allowlist", placeholder="192.0.2.0/24"
            )

    st.markdown(_dashboard_theme_css(), unsafe_allow_html=True)
    if source == "Upload a log file" and upload is None:
        _render_brand_header(st, "Overview")
        st.info("Choose a local log file in the sidebar to begin analysis.")
        return

    if upload is not None:
        report_dir = PROJECT_DIR / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="sshlog-dashboard-", dir=report_dir) as temp_dir:
            input_path = Path(temp_dir) / Path(upload.name).name
            input_path.write_bytes(upload.getvalue())
            _show_soc_navigation(
                st,
                input_path,
                log_type,
                int(year),
                config,
                allowlist_text,
                threshold,
                window_seconds,
                input_source=source,
            )
    elif selected_path is not None:
        _show_soc_navigation(
            st,
            selected_path,
            log_type,
            int(year),
            config,
            allowlist_text,
            threshold,
            window_seconds,
            input_source=source,
        )


def _show_analysis(
    st: Any,
    path: Path,
    log_type: str,
    year: int,
    config: dict[str, Any],
    allowlist_text: str,
    threshold: int,
    window_seconds: int,
    preloaded: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]] | None = None,
) -> None:
    """Show the legacy all-in-one investigation view with optional shared data."""
    if preloaded is None:
        try:
            preloaded = analyze_for_dashboard(
                path,
                log_type=log_type,
                year=year,
                config=config,
                allowlist_text=allowlist_text,
                threshold=threshold,
                window_seconds=window_seconds,
            )
        except (OSError, ValueError) as error:
            st.error(f"Unable to analyze log: {error}")
            return
    events, parse_stats, result = preloaded
    _render_brand_header(st, "Detailed Analysis")

    with st.sidebar:
        all_sources = list(result["risk_scores"])
        selected_source = st.selectbox(
            "Source IP",
            ["All sources", *all_sources],
            help="Limit the dashboard to one source IP and its related alerts/incidents.",
        )
        date_selection = st.date_input(
            "Date range (parsed timestamp)",
            value=(),
            help="Filter events and alert windows by their parsed timestamp values.",
        )
        start_date = end_date = None
        if isinstance(date_selection, tuple):
            if len(date_selection) == 2:
                start_date, end_date = date_selection
        elif isinstance(date_selection, date):
            start_date = end_date = date_selection

    selected_severity = st.multiselect(
        "Filter by rule severity",
        SEVERITIES,
        default=list(SEVERITIES),
        help="Filters alert counts by each detection rule's base severity.",
    )
    selected_ip = None if selected_source == "All sources" else selected_source
    visible_events, visible_result = filter_dashboard_data(
        events,
        result,
        source_ip=selected_ip,
        start_date=start_date,
        end_date=end_date,
        severities=set(selected_severity),
    )
    visible_alerts = visible_result["alerts"]
    visible_risks = visible_result["risk_scores"]
    visible_incidents = visible_result["incidents"]
    metrics = summarize_dashboard_metrics(visible_alerts, visible_risks, visible_incidents)

    st.caption(
        "Rule severity counts describe individual detections; source-risk counts are unique IPs. "
        "Timestamp values use the parsed timestamp basis described in Settings."
    )
    metric_labels = (
        ("Critical alerts", "critical_alerts", "critical"),
        ("High alerts", "high_alerts", "high"),
        ("Medium alerts", "medium_alerts", "medium"),
        ("Low alerts", "low_alerts", "low"),
        ("Critical-risk IPs", "critical_risk_sources", "critical"),
        ("Incidents", "incidents", "info"),
    )
    _render_metric_grid(st, [(label, metrics[key], tone) for label, key, tone in metric_labels])

    st.subheader("Parser coverage (entire input file)")
    lines_read = parse_stats.get("lines_read", 0)
    parsed = parse_stats.get("events_parsed", 0)
    effective_events = parse_stats.get(
        "effective_event_occurrences", effective_event_occurrences(events)
    )
    malformed = parse_stats.get("lines_malformed", 0)
    ignored = parse_stats.get("lines_ignored", 0)
    parsed_pct = (100.0 * parsed / lines_read) if lines_read else 0.0
    malformed_pct = (100.0 * malformed / lines_read) if lines_read else 0.0
    _render_metric_grid(
        st,
        (
            ("Lines read", lines_read, "info"),
            ("Parsed records", parsed, "info"),
            ("Effective occurrences", effective_events, "info"),
            ("Ignored lines", ignored, "good"),
            ("Malformed lines", malformed, "high"),
            (
                "Effective authentication attempts",
                parse_stats.get("effective_authentication_attempts", 0),
                "info",
            ),
            (
                "Authentication failures (all methods)",
                parse_stats.get("authentication_failures", 0),
                "high",
            ),
            ("Password failures", parse_stats.get("password_authentication_failures", 0), "high"),
            ("Failed none probes", parse_stats.get("authentication_method_probes", 0), "info"),
            ("Authentication successes", parse_stats.get("authentication_successes", 0), "good"),
            (
                "Root failures (all methods)",
                parse_stats.get("root_authentication_failures", 0),
                "critical",
            ),
            (
                "Root password failures",
                parse_stats.get("root_password_authentication_failures", 0),
                "critical",
            ),
            ("Root successes", parse_stats.get("root_authentication_successes", 0), "good"),
            (
                "Authentication context records",
                parse_stats.get("authentication_context_records", 0),
                "info",
            ),
            (
                "Context records linked",
                parse_stats.get("supporting_evidence_records", 0),
                "info",
            ),
            (
                "Unattributed context records",
                parse_stats.get("unattributed_contextual_records", 0),
                "info",
            ),
            (
                "Records without direct source IP",
                parse_stats.get("records_without_direct_source_ip", 0),
                "info",
            ),
            (
                "Unresolved/ambiguous context",
                parse_stats.get("unresolved_or_ambiguous_context_records", 0),
                "high",
            ),
            ("Parsed lines (%)", f"{parsed_pct:.1f}%", "info"),
            ("Malformed lines (%)", f"{malformed_pct:.1f}%", "high"),
        ),
    )
    if lines_read and malformed_pct > 5:
        st.warning(f"Malformed SSH/web records are {malformed_pct:.1f}% of input lines (over 5%).")
    if lines_read == 0:
        st.info("The selected log is empty.")
    elif parsed == 0:
        st.warning("No recognizable events were parsed; check the selected log type and format.")
    elif not visible_alerts:
        st.info("Events were parsed, but no alerts matched the current filters.")
    st.caption(
        "Parsed records count retained lines; effective occurrences include repeated-message "
        "weights, while authentication attempts count terminal Accepted/Failed outcomes only. "
        "Percentages use lines read as the denominator. "
        "Ignored lines are outside the selected parser's event scope."
    )
    if malformed:
        with st.expander(f"Malformed record details ({malformed} lines)"):
            render_dashboard_table(
                st, malformed_summary_rows(parse_stats), width="stretch", hide_index=True
            )
            samples = parse_stats.get("malformed_records", [])
            if samples:
                render_dashboard_table(st, samples, width="stretch", hide_index=True)
            omitted = parse_stats.get("malformed_records_truncated", 0)
            if omitted:
                st.caption(
                    f"{omitted} additional line locations are not shown (sample limit: 100)."
                )

    st.subheader("Alerts")
    visible_alerts = sorted(
        visible_alerts,
        key=lambda alert: (
            -(visible_risks.get(alert.get("source_ip"), {}).get("score", -1)),
            str(alert.get("first_seen") or ""),
            str(alert.get("rule") or ""),
        ),
    )
    alert_rows = [
        {
            "Rule": alert.get("rule"),
            "Rule severity": alert.get("base_severity", alert.get("severity")),
            "Source IP": alert.get("source_ip"),
            "First seen (parsed timestamp)": alert.get("first_seen"),
            "Last seen (parsed timestamp)": alert.get("last_seen"),
            "Attempts": alert.get("attempt_count"),
            "Source risk score": visible_risks.get(alert.get("source_ip"), {}).get("score"),
            "Source risk band": visible_risks.get(alert.get("source_ip"), {}).get("band"),
            "Usernames": ", ".join(alert.get("usernames_targeted", [])),
            "Details": alert.get("description"),
        }
        for alert in visible_alerts
    ]
    render_dashboard_table(st, alert_rows, width="stretch", height=420, hide_index=True)

    if selected_ip and selected_ip in visible_risks:
        risk = visible_risks[selected_ip]
        source_alerts = [
            alert
            for alert in visible_alerts
            if alert.get("source_ip") == selected_ip or selected_ip in alert.get("source_ips", [])
        ]
        st.subheader(f"Source investigation: {html.escape(selected_ip)}")
        st.write(f"Risk: {risk['score']}/100 ({risk['band']})")
        st.write(
            "Contributing rules: "
            + (", ".join(sorted({a["rule"] for a in source_alerts})) or "None in current filters")
        )
        st.write(
            "Incident history: "
            + (
                ", ".join(
                    i["incident_id"] for i in visible_incidents if i["source_ip"] == selected_ip
                )
                or "None in current filters"
            )
        )

    st.subheader("Incidents")
    incident_rows = [
        {
            "Incident ID": incident["incident_id"],
            "Source IP": incident["source_ip"],
            "First seen (parsed timestamp)": incident["first_seen"],
            "Last seen (parsed timestamp)": incident["last_seen"],
            "Severity": incident["combined_severity"],
            "Source risk": f"{incident.get('risk_score', 'n/a')}/100 {incident.get('risk_band', '')}",
            "Rules": ", ".join(incident["contributing_rules"]),
            "Attempts": incident.get("attempt_count", "n/a"),
            "Usernames": ", ".join(incident.get("usernames_targeted", [])) or "n/a",
            "Auth methods": ", ".join(incident.get("authentication_methods", []))
            or "Not available in parsed events",
            "SSH session context": incident.get("session_activity", []),
        }
        for incident in visible_incidents
    ]
    render_dashboard_table(st, incident_rows, width="stretch", height=240, hide_index=True)
    if visible_incidents:
        selected_id = st.selectbox(
            "Incident details",
            [item["incident_id"] for item in visible_incidents],
            key="incident_selection",
        )
        incident = next(item for item in visible_incidents if item["incident_id"] == selected_id)
        st.markdown(
            f"**{html.escape(incident['incident_id'])} · {html.escape(incident['combined_severity'])}**  "
            f"Source: `{html.escape(incident['source_ip'])}` · "
            f"{html.escape(str(incident['first_seen']))} – {html.escape(str(incident['last_seen']))} parsed timestamp"
        )
        st.write(incident["summary"])
        if incident.get("session_activity"):
            st.write("Matching SSH session context", incident["session_activity"])
        if incident.get("supporting_evidence"):
            st.write("Supporting authentication context", incident["supporting_evidence"])
    else:
        st.info("No correlated incidents match the current filters.")

    st.subheader("Failed attempts over time")
    focus_options = {"All visible events": None}
    for incident in visible_incidents:
        focus_options[f"Incident {incident['incident_id']} ({incident['source_ip']})"] = (
            incident["source_ip"],
            incident["first_seen"],
            incident["last_seen"],
        )
    for index, alert in enumerate(visible_alerts, start=1):
        focus_options[
            f"Alert {index}: {alert['rule']} ({alert.get('source_ip') or 'distributed'})"
        ] = (alert.get("source_ip"), alert.get("first_seen"), alert.get("last_seen"))
    focus_label = st.selectbox("Timeline scope", list(focus_options), key="timeline_scope")
    focus = focus_options[focus_label]
    chart_events = visible_events
    if focus is not None:
        focus_ip, focus_first, focus_last = focus
        first = _as_datetime(focus_first)
        last = _as_datetime(focus_last)
        chart_events = [
            event
            for event in visible_events
            if (focus_ip is None or event.get("source_ip") == focus_ip)
            and (stamp := _as_datetime(event.get("timestamp"))) is not None
            and (first is None or stamp >= first)
            and (last is None or stamp <= last)
        ]
    hourly = _attempts_by_hour(chart_events)
    if hourly:
        log_scale = st.checkbox("Logarithmic attempt scale", value=False)
        attempts_chart = _detailed_attempts_chart(chart_events, log_scale=log_scale)
        if attempts_chart is not None:
            st.altair_chart(attempts_chart, width="stretch")
        source_chart = _detailed_source_activity_chart(chart_events)
        if source_chart is not None:
            st.caption("The source view shows the five most active observed sources in this scope.")
            st.altair_chart(source_chart, width="stretch")
        else:
            st.caption("No source-attributed failed activity is available for this scope.")
    else:
        st.info("No timestamped failed attempts are available for the current filters.")

    st.subheader("Top source IPs and risk")
    risk_rows = list(visible_risks.items())[:10]
    if not risk_rows:
        st.info("No source risk scores are available for the current filters.")
    for ip, risk in risk_rows:
        source_columns = st.columns((2, 1, 1))
        source_columns[0].write(ip)
        source_columns[1].metric("Risk score", f"{risk['score']}/100")
        badge = risk_band_badge(risk["band"])
        source_columns[2].write("Risk band")
        source_columns[2].badge(badge["label"], color=badge["color"])

    username_rows, root_counts = _root_and_username_summary(visible_events)
    st.subheader("Username and root-login analytics")
    render_dashboard_table(st, username_rows, width="stretch", hide_index=True)
    st.write(
        f"Failed root attempts: {root_counts['failed']} · Successful root logins: {root_counts['successful']}"
    )

    success_alerts = [
        alert
        for alert in visible_alerts
        if alert.get("rule") in {"ssh_success_after_failures", "web_success_after_failures"}
    ]
    if success_alerts:
        strongest = max(success_alerts, key=lambda alert: alert.get("attempt_count", 0))
        st.warning(
            "Potential compromise indicator: successful authentication was observed after "
            f"{strongest.get('attempt_count', 0)} failed attempts from "
            f"{html.escape(str(strongest.get('source_ip') or 'the same source'))}. "
            "This sequence is suspicious activity, not confirmation of compromise."
        )

    payload = json.dumps(_output_value(visible_result), indent=2, ensure_ascii=False)
    csv_payload = render_csv(visible_alerts, visible_result.get("timestamp_interpretation"))
    login_csv_payload = render_successful_logins_csv(visible_result.get("successful_logins", []))
    from html_report import render_html_report

    html_payload = render_html_report(visible_events, visible_result)
    download_columns = st.columns(4)
    download_columns[0].download_button(
        "Download filtered JSON", payload, file_name="alerts.json", mime="application/json"
    )
    download_columns[1].download_button(
        "Download filtered CSV", csv_payload, file_name="alerts.csv", mime="text/csv"
    )
    download_columns[2].download_button(
        "Download successful logins CSV",
        login_csv_payload,
        file_name="successful_logins.csv",
        mime="text/csv",
    )
    download_columns[3].download_button(
        "Download filtered HTML", html_payload, file_name="report.html", mime="text/html"
    )


def main() -> None:
    """Start the local Streamlit dashboard with telemetry disabled."""
    os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
    import streamlit as st

    _render_dashboard(st)


if __name__ == "__main__":
    main()
