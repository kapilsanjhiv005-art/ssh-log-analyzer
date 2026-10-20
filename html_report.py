"""Build a self-contained, escaped HTML report with embedded PNG charts."""

from __future__ import annotations

import base64
import html
import io
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib

from event_accounting import effective_event_occurrences, event_occurrences

matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402


def _escape(value: Any) -> str:
    """Escape dynamic content before placing it in HTML text nodes."""
    if value is None:
        value = ""
    if isinstance(value, (list, tuple, dict)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return html.escape(str(value), quote=True)


def _failed(event: dict[str, Any]) -> bool:
    """Return whether an SSH or web event represents a failed attempt."""
    if event.get("event_type") == "authentication_failure":
        return True
    return event.get("status") in (401, 403, 404)


def _chart_data(events: list[dict[str, Any]], risk_scores: dict[str, Any]) -> tuple[str, str]:
    """Render failure timeline and top-IP plots to base64 PNG strings."""
    failures = [event for event in events if _failed(event)]
    figure, axis = plt.subplots(figsize=(8, 2.8), constrained_layout=True)
    if failures:
        counts = Counter()
        for event in failures:
            stamp = event["timestamp"]
            if not isinstance(stamp, datetime):
                stamp = datetime.fromisoformat(stamp)
            counts[stamp.replace(minute=0, second=0, microsecond=0)] += event_occurrences(event)
        x_values = sorted(counts)
        axis.plot(x_values, [counts[x] for x in x_values], marker="o", color="#2673a8")
        axis.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M", tz=timezone.utc))
        figure.autofmt_xdate()
        axis.set_ylabel("Failed events")
    else:
        axis.text(
            0.5, 0.5, "No failed attempts", ha="center", va="center", transform=axis.transAxes
        )
        axis.set_xticks([])
        axis.set_yticks([])
    axis.set_title("Failed attempts over time")
    image_one = io.BytesIO()
    figure.savefig(image_one, format="png", dpi=120)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(8, 2.8), constrained_layout=True)
    top_ips = list(risk_scores.items())[:10]
    if top_ips:
        ips = [ip for ip, _ in top_ips][::-1]
        scores = [risk["score"] for _, risk in top_ips][::-1]
        axis.barh(ips, scores, color="#4a8f70")
        axis.set_xlim(0, 100)
        axis.set_xlabel("Risk score")
    else:
        axis.text(0.5, 0.5, "No source IPs", ha="center", va="center", transform=axis.transAxes)
        axis.set_xticks([])
        axis.set_yticks([])
    axis.set_title("Top source IPs by risk")
    image_two = io.BytesIO()
    figure.savefig(image_two, format="png", dpi=120)
    plt.close(figure)
    return (
        base64.b64encode(image_one.getvalue()).decode("ascii"),
        base64.b64encode(image_two.getvalue()).decode("ascii"),
    )


def render_html_report(events: list[dict[str, Any]], result: dict[str, Any]) -> str:
    """Return standalone HTML for summary, incidents, alerts, timeline, and config."""
    alerts = result.get("alerts", [])
    incidents = result.get("incidents", [])
    successful_logins = result.get("successful_logins", [])
    risk_explanations = result.get("risk_explanations", {})
    risks = result.get("risk_scores", {})
    severity_counts = Counter(alert.get("base_severity", alert["severity"]) for alert in alerts)
    parse_stats = result.get("parse_stats", {})
    chart_timeline, chart_ips = _chart_data(events, risks)

    incident_rows = (
        "".join(
            "<tr>"
            f"<td>{_escape(item.get('incident_id'))}</td>"
            f"<td>{_escape(item.get('combined_severity'))}</td>"
            f"<td>{_escape(item.get('risk_score', 'n/a'))}</td>"
            f"<td>{_escape(item.get('risk_band', 'n/a'))}</td>"
            f"<td>{_escape(item.get('source_ip'))}</td>"
            f"<td>{_escape(item.get('first_seen'))}</td>"
            f"<td>{_escape(item.get('last_seen'))}</td>"
            f"<td>{_escape(item.get('attempt_count', 'n/a'))}</td>"
            f"<td>{_escape(item.get('usernames_targeted', []))}</td>"
            f"<td>{_escape(item.get('authentication_methods', []))}</td>"
            f"<td>{_escape(item.get('session_activity', []))}</td>"
            f"<td>{_escape(item.get('supporting_evidence', []))}</td>"
            f"<td>{_escape(item.get('contributing_rules'))}</td>"
            f"<td>{_escape(item.get('summary'))}</td></tr>"
            for item in incidents
        )
        or '<tr><td colspan="14">No correlated incidents.</td></tr>'
    )

    successful_login_rows = (
        "".join(
            "<tr>"
            f"<td>{_escape(row.get('timestamp'))}</td>"
            f"<td>{_escape(row.get('source_ip') or 'Unavailable')}</td>"
            f"<td>{_escape(row.get('username') or 'Unavailable')}</td>"
            f"<td>{_escape(row.get('hostname') or 'Unavailable')}</td>"
            f"<td>{_escape(row.get('process_id') if row.get('process_id') is not None else 'Unavailable')}</td>"
            f"<td>{_escape(row.get('session_identifier') or 'Unavailable in source log')}</td>"
            f"<td>{_escape(row.get('duration_seconds') if row.get('duration_seconds') is not None else 'Unavailable')}</td>"
            f"<td>{_escape(row.get('related_failures') if row.get('related_failures') is not None else 'Unavailable')}</td>"
            f"<td>{_escape(row.get('related_alert_rules', []))}</td>"
            f"<td>{_escape(row.get('correlation_status'))}</td>"
            f"<td>{_escape(row.get('data_quality_limitations', []))}</td></tr>"
            for row in successful_logins
        )
        or '<tr><td colspan="11">No successful logins were recorded.</td></tr>'
    )

    risk_rows = (
        "".join(
            f"<tr><td>{_escape(ip)}</td><td>{_escape(risk.get('score'))}</td>"
            f"<td>{_escape(risk.get('band'))}</td></tr>"
            for ip, risk in list(risks.items())[:10]
        )
        or '<tr><td colspan="3">No source IPs.</td></tr>'
    )

    explanation_rows = []
    for source_ip, explanation in risk_explanations.items():
        for name, factor in explanation.get("factors", {}).items():
            explanation_rows.append(
                "<tr>"
                f"<td>{_escape(source_ip)}</td>"
                f"<td>{_escape(explanation.get('score'))}/100 {_escape(explanation.get('band'))}</td>"
                f"<td>{_escape(name.replace('_', ' ').title())}</td>"
                f"<td>{_escape(factor.get('evidence'))}</td>"
                f"<td>{_escape(factor.get('contribution'))}</td>"
                f"<td>{_escape(factor.get('policy'))}</td></tr>"
            )
        explanation_rows.append(
            "<tr>"
            f"<td>{_escape(source_ip)}</td><td>{_escape(explanation.get('score'))}/100 {_escape(explanation.get('band'))}</td>"
            "<td>Confidence and uncertainty</td>"
            f'<td colspan="2">{_escape(explanation.get("confidence", {}).get("rationale"))}</td>'
            f"<td>{_escape(explanation.get('uncertainty'))}</td></tr>"
        )
    explanation_table = (
        "".join(explanation_rows)
        or '<tr><td colspan="6">No source-risk explanations are available.</td></tr>'
    )

    alert_rows = []
    timeline_rows = []
    for alert in alerts:
        extra = []
        for field, label in (
            ("path", "Path"),
            ("user_agent", "User agent"),
            ("referrer", "Referrer"),
            ("authentication_methods", "Authentication methods"),
            ("mitre_mapping_note", "ATT&CK mapping note"),
        ):
            if alert.get(field):
                extra.append(f"<div><b>{label}:</b> {_escape(alert[field])}</div>")
        extra.append(f"<div><b>Usernames:</b> {_escape(alert.get('usernames_targeted', []))}</div>")
        if alert.get("session_activity"):
            extra.append(
                "<div><b>Matching SSH session context:</b> "
                f"{_escape(alert['session_activity'])}</div>"
            )
        if alert.get("supporting_evidence"):
            extra.append(
                "<div><b>Supporting authentication context:</b> "
                f"{_escape(alert['supporting_evidence'])}</div>"
            )
        alert_rows.append(
            "<tr>"
            f"<td>{_escape(alert.get('rule'))}</td>"
            f"<td>{_escape(alert.get('base_severity', alert.get('severity')))}</td>"
            f"<td>{_escape(alert.get('source_ip'))}</td>"
            f"<td>{_escape(alert.get('first_seen'))}</td><td>{_escape(alert.get('last_seen'))}</td>"
            f"<td>{_escape(alert.get('attempt_count'))}</td>"
            f"<td>{_escape(alert.get('description'))}"
            f"<div><b>Composite source risk:</b> "
            f"{_escape(alert.get('source_risk_score', alert.get('risk_score', 'n/a')))}/100 "
            f"{_escape(alert.get('source_risk_band', alert.get('risk_band', 'n/a')))}</div>{''.join(extra)}"
            f"<div><b>Action:</b> {_escape(alert.get('recommended_action'))}</div></td></tr>"
        )
        timeline_rows.append(
            f"<li><time>{_escape(alert.get('first_seen'))}</time> — "
            f"<b>{_escape(alert.get('base_severity', alert.get('severity')))} base severity</b> "
            f"{_escape(alert.get('rule'))} "
            f"from {_escape(alert.get('source_ip'))}</li>"
        )
    alert_table = "".join(alert_rows) or '<tr><td colspan="7">No alerts were generated.</td></tr>'
    timeline = "".join(timeline_rows) or "<li>No alerts to show on the timeline.</li>"
    severity_html = "".join(
        f"<li>{_escape(severity)}: {_escape(severity_counts.get(severity, 0))}</li>"
        for severity in ("Critical", "High", "Medium", "Low")
    )
    config_json = _escape(result.get("config_used", {}))
    timestamp_metadata = _escape(result.get("timestamp_interpretation", {}))
    generated = _escape(result.get("generated_at", datetime.now().astimezone().isoformat()))
    effective_count = parse_stats.get(
        "effective_event_occurrences", effective_event_occurrences(events)
    )
    stats_summary = (
        f"{_escape(parse_stats.get('lines_read', 0))} lines read, "
        f"{_escape(parse_stats.get('events_parsed', 0))} records parsed, "
        f"{_escape(effective_count)} effective occurrences, "
        f"{_escape(parse_stats.get('lines_ignored', 0))} ignored, "
        f"{_escape(parse_stats.get('lines_malformed', 0))} malformed"
    )
    if "authentication_failures" in parse_stats:
        stats_summary += (
            f"; {_escape(parse_stats.get('effective_authentication_attempts', 0))} terminal authentication attempts, "
            f"{_escape(parse_stats['authentication_failures'])} failures across methods, "
            f"{_escape(parse_stats.get('password_authentication_failures', 0))} password failures, "
            f"{_escape(parse_stats.get('authentication_method_probes', 0))} Failed none probes, "
            f"{_escape(parse_stats['authentication_successes'])} successes, "
            f"{_escape(parse_stats['root_authentication_failures'])} root failures across methods, "
            f"{_escape(parse_stats.get('root_password_authentication_failures', 0))} root password failures, "
            f"{_escape(parse_stats['root_authentication_successes'])} root successes"
            f", {_escape(parse_stats.get('authentication_context_records', 0))} auth-context records"
            f", {_escape(parse_stats.get('supporting_evidence_records', 0))} linked to outcomes"
            f", {_escape(parse_stats.get('unattributed_contextual_records', 0))} unattributed context"
            f", {_escape(parse_stats.get('unresolved_or_ambiguous_context_records', 0))} unresolved/ambiguous context"
            f"; {_escape(parse_stats.get('authentication_context_categories', {}).get('invalid_user', 0))} invalid-user context, "
            f"{_escape(parse_stats.get('authentication_context_categories', {}).get('pam_authentication_failure', 0))} PAM context, "
            f"{_escape(parse_stats.get('authentication_context_categories', {}).get('input_userauth_request', 0))} sshd auth-request context"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Log Analysis Report</title>
<style>
body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#1b2730;background:#f7f9fb}}
h1,h2{{color:#183c54}}section{{background:white;border:1px solid #dbe3e8;border-radius:8px;padding:1rem 1.25rem;margin:1rem 0;overflow-x:auto}}
table{{border-collapse:collapse;width:100%;font-size:.92rem}}th,td{{border:1px solid #dbe3e8;padding:.55rem;text-align:left;vertical-align:top}}th{{background:#eaf1f5}}
.metrics{{display:flex;flex-wrap:wrap;gap:2rem}}.metric{{min-width:140px}}.charts img{{display:block;width:min(100%,900px);height:auto;margin:1rem 0}}
li{{margin:.35rem 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}small{{color:#52616b}}
</style></head><body>
<h1>Security Log Analysis Report</h1><small>Generated {_escape(generated)} · Version {_escape(result.get("version", ""))}</small>
<section><h2>Summary</h2><div class="metrics"><div class="metric"><b>{len(alerts)}</b><br>Alerts</div>
<div class="metric"><b>{len(incidents)}</b><br>Incidents</div><div class="metric"><b>{_escape(stats_summary)}</b><br>Parser coverage</div>
<div class="metric"><b>{_escape(result.get("alerts_suppressed", 0))}</b><br>Alerts suppressed by allowlist</div></div>
<h3>Alert base-severity counts</h3><ul>{severity_html}</ul></section>
<section><h2>Successful logins</h2><p>A successful authentication alone is not proof of malicious activity or compromise. Durations require a unique host/PID/username lifecycle match.</p><table><thead><tr><th>Timestamp</th><th>Source IP</th><th>Username</th><th>Host</th><th>sshd PID</th><th>Session ID</th><th>Duration from auth</th><th>Related failures</th><th>Related alerts</th><th>Linkage</th><th>Data-quality limits</th></tr></thead><tbody>{successful_login_rows}</tbody></table></section>
<section><h2>Incidents</h2><table><thead><tr><th>ID</th><th>Composite severity</th><th>Risk score</th><th>Risk band</th><th>Source IP</th><th>First seen</th><th>Last seen</th><th>Attempts</th><th>Targeted usernames</th><th>Authentication methods</th><th>SSH session context</th><th>Supporting authentication context</th><th>Rules</th><th>Summary</th></tr></thead><tbody>{incident_rows}</tbody></table></section>
<section><h2>Source-risk explanations</h2><p>Confidence is not calibrated and is not a probability of compromise. Source risk remains distinct from rule severity and incident severity.</p><table><thead><tr><th>Source IP</th><th>Score / band</th><th>Factor</th><th>Evidence</th><th>Contribution</th><th>Policy / uncertainty</th></tr></thead><tbody>{explanation_table}</tbody></table></section>
<section><h2>Top risky IPs</h2><table><thead><tr><th>Source IP</th><th>Score</th><th>Band</th></tr></thead><tbody>{risk_rows}</tbody></table></section>
<section class="charts"><h2>Charts</h2><img alt="Failed attempts over time" src="data:image/png;base64,{chart_timeline}"><img alt="Top source IPs by risk" src="data:image/png;base64,{chart_ips}"></section>
<section><h2>Alert timeline</h2><ol>{timeline}</ol></section>
<section><h2>Alert details</h2><table><thead><tr><th>Rule</th><th>Base severity</th><th>Source IP</th><th>First seen</th><th>Last seen</th><th>Attempts</th><th>Details and recommended action</th></tr></thead><tbody>{alert_table}</tbody></table></section>
<section><h2>Timestamp interpretation</h2><pre>{timestamp_metadata}</pre></section>
<section><h2>Configuration used</h2><pre>{config_json}</pre></section>
</body></html>"""


def export_html_report(
    events: list[dict[str, Any]], result: dict[str, Any], output_path: str | Path
) -> Path:
    """Write the self-contained report and return its path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(events, result), encoding="utf-8")
    return path
