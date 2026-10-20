"""Render a plain Markdown report from shared analysis results."""

from __future__ import annotations

import html
import re
from collections import Counter
from typing import Any


def _markdown_cell(value: Any) -> str:
    """Escape untrusted values for Markdown table cells and HTML renderers."""
    text = html.escape(str(value if value is not None else ""), quote=True)
    text = re.sub(r"([\\`*_{}\[\]()#+.!>~-])", r"\\\1", text)
    return text.replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def render_markdown_report(result: dict[str, Any]) -> str:
    """Return deterministic Markdown for alerts, incidents, risk, and coverage."""
    alerts = result.get("alerts", [])
    incidents = result.get("incidents", [])
    successful_logins = result.get("successful_logins", [])
    risk_explanations = result.get("risk_explanations", {})
    stats = result.get("parse_stats", {})
    risk_scores = result.get("risk_scores", {})
    severity_counts = Counter(
        alert.get("base_severity", alert.get("severity", "Unknown")) for alert in alerts
    )
    lines = [
        "# Security Log Analysis Report",
        "",
        "## Summary",
        "",
        f"- Alerts: {len(alerts)}",
        f"- Incidents: {len(incidents)}",
        "- Alert base severities: "
        + _markdown_cell(
            ", ".join(
                f"{severity} {severity_counts.get(severity, 0)}"
                for severity in ("Critical", "High", "Medium", "Low")
            )
        ),
        f"- Lines read: {stats.get('lines_read', 0)}",
        f"- Parsed records: {stats.get('events_parsed', 0)}",
        f"- Effective event occurrences: {stats.get('effective_event_occurrences', 0)}",
        f"- Ignored lines: {stats.get('lines_ignored', 0)}",
        f"- Malformed lines: {stats.get('lines_malformed', 0)}",
    ]
    if "authentication_failures" in stats:
        lines.extend(
            (
                f"- Authentication failures across methods: {stats.get('authentication_failures', 0)}",
                f"- Password failures: {stats.get('password_authentication_failures', 0)}",
                f"- Failed none probes: {stats.get('authentication_method_probes', 0)}",
                f"- Authentication successes: {stats.get('authentication_successes', 0)}",
                f"- Root password failures: {stats.get('root_password_authentication_failures', 0)}",
                f"- Invalid-user context records: {stats.get('authentication_context_categories', {}).get('invalid_user', 0)}",
                f"- PAM auth-failure context records: {stats.get('authentication_context_categories', {}).get('pam_authentication_failure', 0)}",
                f"- input_userauth_request records: {stats.get('authentication_context_categories', {}).get('input_userauth_request', 0)}",
                f"- Connection-closed records: {stats.get('parsed_record_categories', {}).get('connection_closed', 0)}",
                f"- Identification-missing records: {stats.get('parsed_record_categories', {}).get('identification_missing', 0)}",
            )
        )
    timestamp_metadata = result.get("timestamp_interpretation")
    if timestamp_metadata:
        lines.extend(
            (
                "",
                "## Timestamp interpretation",
                "",
                f"- Year for yearless SSH timestamps: {_markdown_cell(timestamp_metadata.get('year_for_yearless_timestamps') if timestamp_metadata.get('year_for_yearless_timestamps') is not None else 'Not applicable')}",
                f"- Timezone assumption: {_markdown_cell(timestamp_metadata.get('timezone_assumption', 'Unavailable'))}",
                f"- Offset handling: {_markdown_cell(timestamp_metadata.get('offset_timestamp_policy', 'Unavailable'))}",
            )
        )
    lines.extend(("", "## Source-risk explanations", ""))
    if risk_explanations:
        for source_ip, explanation in risk_explanations.items():
            lines.append(
                f"### {_markdown_cell(source_ip)} — {_markdown_cell(explanation.get('score'))}/100 "
                f"{_markdown_cell(explanation.get('band'))}"
            )
            lines.append("")
            lines.append("| Factor | Evidence | Contribution | Policy |")
            lines.append("|---|---:|---:|---|")
            for name, factor in explanation.get("factors", {}).items():
                values = (
                    name.replace("_", " ").title(),
                    factor.get("evidence"),
                    factor.get("contribution"),
                    factor.get("policy"),
                )
                lines.append("| " + " | ".join(_markdown_cell(value) for value in values) + " |")
            lines.append(
                "Confidence is not calibrated: "
                + _markdown_cell(explanation.get("confidence", {}).get("rationale", "Unavailable"))
            )
            lines.append(
                "Uncertainty: " + _markdown_cell(explanation.get("uncertainty", "Unavailable"))
            )
            lines.append("")
    else:
        lines.append("No source-risk explanations are available.")
    lines.extend(
        (
            "",
            "## Successful logins",
            "",
            "A successful authentication alone is not proof of malicious activity or compromise. "
            "Session duration requires a unique host/PID/username lifecycle match.",
            "",
            "| Timestamp | Source IP | Username | Host | sshd PID | Session ID | Duration from auth (seconds) | Related failures | Related alerts | Linkage and limitations |",
            "|---|---|---|---:|---|---|---:|---:|---|---|",
        )
    )
    if successful_logins:
        for login in successful_logins:
            related = (
                str(login.get("correlation_status", ""))
                + "; "
                + "; ".join(login.get("data_quality_limitations", []))
            )
            values = (
                login.get("timestamp"),
                login.get("source_ip") or "Unavailable",
                login.get("username") or "Unavailable",
                login.get("hostname") or "Unavailable",
                login.get("process_id") if login.get("process_id") is not None else "Unavailable",
                login.get("session_identifier") or "Unavailable in source log",
                login.get("duration_seconds")
                if login.get("duration_seconds") is not None
                else "Unavailable",
                login.get("related_failures")
                if login.get("related_failures") is not None
                else "Unavailable",
                ", ".join(login.get("related_alert_rules", [])) or "None",
                related,
            )
            lines.append("| " + " | ".join(_markdown_cell(value) for value in values) + " |")
    else:
        lines.append("| — | — | — | — | — | — | — | — | — | No successful logins were recorded |")
    if "authentication_failures" in stats:
        lines.extend(
            (
                f"- Terminal authentication attempts: {stats.get('effective_authentication_attempts', 0)}",
                f"- Failed authentication attempts: {stats['authentication_failures']}",
                f"- Successful authentication attempts: {stats['authentication_successes']}",
                f"- Root authentication failures: {stats['root_authentication_failures']}",
                f"- Root authentication successes: {stats['root_authentication_successes']}",
                f"- Authentication context records: {stats.get('authentication_context_records', 0)}",
                f"- Context records linked to outcomes: {stats.get('supporting_evidence_records', 0)}",
                f"- Unattributed contextual records: {stats.get('unattributed_contextual_records', 0)}",
                f"- Unresolved or ambiguous context records: {stats.get('unresolved_or_ambiguous_context_records', 0)}",
            )
        )
    lines.extend(
        (
            "",
            "## Incidents",
            "",
            "| ID | Source | Severity | Risk score / band | Attempts | First seen (parsed time) | Last seen (parsed time) | Session context | Supporting authentication context | Rules |",
            "|---|---|---|---:|---:|---|---|---|---|---|",
        )
    )
    if incidents:
        for incident in incidents:
            cells = (
                incident.get("incident_id"),
                incident.get("source_ip"),
                incident.get("combined_severity"),
                f"{incident.get('risk_score', 'n/a')} / {incident.get('risk_band', 'n/a')}",
                incident.get("attempt_count"),
                incident.get("first_seen"),
                incident.get("last_seen"),
                incident.get("session_activity", ""),
                incident.get("supporting_evidence", ""),
                ", ".join(incident.get("contributing_rules", [])),
            )
            lines.append("| " + " | ".join(_markdown_cell(value) for value in cells) + " |")
    else:
        lines.append("| — | — | — | — | — | — | — | — | — | No correlated incidents |")
    lines.extend(
        (
            "",
            "## Alerts",
            "",
            "| Rule | Base severity | Source | Source risk | Attempts | First seen (parsed time) | Details |",
            "|---|---|---|---|---:|---|---|",
        )
    )
    if alerts:
        for alert in alerts:
            risk = risk_scores.get(alert.get("source_ip"), {})
            description = alert.get("description")
            if alert.get("session_activity"):
                description = (
                    f"{description} Matching SSH session context: {alert['session_activity']}"
                )
            if alert.get("supporting_evidence"):
                description = (
                    f"{description} Supporting authentication context: "
                    f"{alert['supporting_evidence']}"
                )
            if alert.get("mitre_mapping_note"):
                description = f"{description} ATT&CK mapping note: {alert['mitre_mapping_note']}"
            cells = (
                alert.get("rule"),
                alert.get("base_severity", alert.get("severity")),
                alert.get("source_ip"),
                f"{risk.get('score', 'n/a')} / {risk.get('band', 'n/a')}",
                alert.get("attempt_count"),
                alert.get("first_seen"),
                description,
            )
            lines.append("| " + " | ".join(_markdown_cell(value) for value in cells) + " |")
    else:
        lines.append("| — | — | — | — | — | — | No alerts were generated |")
    lines.extend(("", "Source risk is distinct from each rule's base severity.", ""))
    return "\n".join(lines)
