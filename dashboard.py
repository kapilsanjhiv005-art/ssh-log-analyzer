"""Local Streamlit dashboard for authorized SSH and web log analysis."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import tempfile
from collections import Counter, defaultdict
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any

from analyzer import VERSION, _output_value, load_input, render_csv
from config import load_config
from detections import analyze_events, calculate_risk_scores, correlate_incidents

PROJECT_DIR = Path(__file__).resolve().parent
SAMPLE_LOGS = {
    "SSH sample": PROJECT_DIR / "sample_logs" / "auth.log",
    "Web sample": PROJECT_DIR / "sample_logs" / "web_access.log",
}
SEVERITIES = ("Critical", "High", "Medium", "Low")
RISK_COLORS = {
    "Low": "#e8f5e9",
    "Medium": "#fff8e1",
    "High": "#fff3e0",
    "Critical": "#ffebee",
}


def risk_band_badge(band: str) -> str:
    """Return a safely escaped, color-coded badge for a risk band."""
    color = RISK_COLORS.get(band, RISK_COLORS["Low"])
    return (
        f'<span style="background:{color};padding:.2rem .5rem;border-radius:.3rem">'
        f"{html.escape(band, quote=True)}</span>"
    )


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
    events, parse_stats = load_input(log_path, log_type, year)
    result = analyze_events(
        events,
        config=settings,
        allowlist=parse_allowlist_text(allowlist_text),
        log_type=log_type,
    )
    result.update(
        {
            "config_used": settings,
            "parse_stats": parse_stats,
            "version": VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
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
            count = event.get("occurrence_count", 1)
            counts[timestamp.replace(minute=0, second=0, microsecond=0)] += (
                count if isinstance(count, int) and count > 0 else 1
            )
    return dict(sorted(counts.items()))


def _as_datetime(value: Any) -> datetime | None:
    """Convert an available event timestamp to the parser's naive-UTC form."""
    if value is None:
        return None
    try:
        timestamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
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
    for alert in result.get("alerts", []):
        sources = {alert.get("source_ip"), *alert.get("source_ips", [])}
        if source_ip is not None and source_ip not in sources:
            continue
        if (
            severities is not None
            and alert.get("base_severity", alert.get("severity")) not in severities
        ):
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
            incident["incident_id"] = matching_originals[0]["incident_id"]
    for incident in incidents:
        first = _as_datetime(incident.get("first_seen"))
        last = _as_datetime(incident.get("last_seen"))
        evidence = [
            event
            for event in visible_events
            if event.get("source_ip") == incident["source_ip"]
            and (stamp := _as_datetime(event.get("timestamp"))) is not None
            and (first is None or stamp >= first)
            and (last is None or stamp <= last)
        ]
        incident["attempt_count"] = sum(
            event.get("occurrence_count", 1)
            if isinstance(event.get("occurrence_count", 1), int)
            and event.get("occurrence_count", 1) > 0
            else 1
            for event in evidence
        )
        incident["usernames_targeted"] = sorted(
            {event["username"] for event in evidence if event.get("username")}
        )
        incident["authentication_methods"] = sorted(
            {
                event["authentication_method"]
                for event in evidence
                if event.get("authentication_method")
            }
        )
    filtered["incidents"] = incidents
    return visible_events, filtered


def _root_and_username_summary(
    events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Count targeted usernames and root outcomes from parsed authentication events."""
    usernames: Counter[str] = Counter()
    root = Counter()
    for event in events:
        if event.get("event_type") not in {"authentication_failure", "authentication_success"}:
            continue
        occurrence_count = event.get("occurrence_count", 1)
        weight = (
            occurrence_count if isinstance(occurrence_count, int) and occurrence_count > 0 else 1
        )
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


def _render_dashboard(st: Any) -> None:
    """Render the local-only Streamlit user interface."""
    st.set_page_config(page_title="Security Log Dashboard", layout="wide")
    st.title("Security Log Analysis Dashboard")
    st.caption("Runs locally; uploaded logs are analyzed in process and are not sent to a service.")

    log_type = st.selectbox("Log type", ("ssh", "web"), format_func=str.upper)
    source = st.radio("Input", ("Sample log", "Upload a log file"), horizontal=True)
    selected_path: Path | None = None
    upload = None
    if source == "Sample log":
        sample_name = "SSH sample" if log_type == "ssh" else "Web sample"
        selected_path = SAMPLE_LOGS[sample_name]
        st.caption(f"Sample: {selected_path.name}")
    else:
        upload = st.file_uploader("Choose a local log file", type=("log", "txt"))
        if upload is None:
            st.info("Upload a log file to begin analysis.")
            return

    config = load_config(PROJECT_DIR / "config.yaml")
    if log_type == "ssh":
        default_threshold = config["brute_force"]["threshold"]
    else:
        default_threshold = config["web"]["login_threshold"]
    with st.sidebar:
        st.header("Analysis settings")
        year = st.number_input("Year for SSH syslog timestamps", 1970, 2200, datetime.now().year)
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

    if upload is not None:
        report_dir = PROJECT_DIR / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="sshlog-dashboard-", dir=report_dir) as temp_dir:
            input_path = Path(temp_dir) / Path(upload.name).name
            input_path.write_bytes(upload.getvalue())
            _show_analysis(
                st,
                input_path,
                log_type,
                int(year),
                config,
                allowlist_text,
                threshold,
                window_seconds,
            )
    elif selected_path is not None:
        _show_analysis(
            st,
            selected_path,
            log_type,
            int(year),
            config,
            allowlist_text,
            threshold,
            window_seconds,
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
) -> None:
    """Analyze a selected local file and show filterable SOC-style evidence."""
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

    with st.sidebar:
        all_sources = list(result["risk_scores"])
        selected_source = st.selectbox(
            "Source IP",
            ["All sources", *all_sources],
            help="Limit the dashboard to one source IP and its related alerts/incidents.",
        )
        date_selection = st.date_input(
            "Date range (UTC)",
            value=(),
            help="Filter events and alert windows by the parser's UTC timestamps.",
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
        "Displayed event timestamps are UTC."
    )
    metric_columns = st.columns(6)
    metric_labels = (
        ("Critical alerts", "critical_alerts"),
        ("High alerts", "high_alerts"),
        ("Medium alerts", "medium_alerts"),
        ("Low alerts", "low_alerts"),
        ("Critical-risk sources", "critical_risk_sources"),
        ("Incidents", "incidents"),
    )
    for column, (label, key) in zip(metric_columns, metric_labels):
        column.metric(label, metrics[key])

    st.subheader("Parser coverage (entire input file)")
    lines_read = parse_stats.get("lines_read", 0)
    parsed = parse_stats.get("events_parsed", 0)
    effective_events = sum(
        event.get("occurrence_count", 1)
        if isinstance(event.get("occurrence_count", 1), int)
        and event.get("occurrence_count", 1) > 0
        else 1
        for event in events
    )
    malformed = parse_stats.get("lines_malformed", 0)
    ignored = parse_stats.get("lines_ignored", 0)
    parsed_pct = (100.0 * parsed / lines_read) if lines_read else 0.0
    malformed_pct = (100.0 * malformed / lines_read) if lines_read else 0.0
    coverage_columns = st.columns(7)
    for column, label, value in zip(
        coverage_columns,
        (
            "Lines read",
            "Parsed records",
            "Effective events",
            "Ignored lines",
            "Malformed lines",
            "Parsed lines",
            "Malformed lines",
        ),
        (
            lines_read,
            parsed,
            effective_events,
            ignored,
            malformed,
            f"{parsed_pct:.1f}%",
            f"{malformed_pct:.1f}%",
        ),
    ):
        column.metric(label, value)
    if lines_read and malformed_pct > 5:
        st.warning(f"Malformed SSH/web records are {malformed_pct:.1f}% of input lines (over 5%).")
    if lines_read == 0:
        st.info("The selected log is empty.")
    elif parsed == 0:
        st.warning("No recognizable events were parsed; check the selected log type and format.")
    elif not visible_alerts:
        st.info("Events were parsed, but no alerts matched the current filters.")
    st.caption(
        "Parsed records count input lines that yielded an event; effective events include "
        "OpenSSH repeated-message counts. Percentages use lines read as the denominator. "
        "Ignored lines are outside the selected parser's event scope."
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
            "First seen (UTC)": alert.get("first_seen"),
            "Last seen (UTC)": alert.get("last_seen"),
            "Attempts": alert.get("attempt_count"),
            "Source risk score": visible_risks.get(alert.get("source_ip"), {}).get("score"),
            "Source risk band": visible_risks.get(alert.get("source_ip"), {}).get("band"),
            "Usernames": ", ".join(alert.get("usernames_targeted", [])),
            "Details": alert.get("description"),
        }
        for alert in visible_alerts
    ]
    st.dataframe(alert_rows, width="stretch", height=420, hide_index=True)

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
            "First seen (UTC)": incident["first_seen"],
            "Last seen (UTC)": incident["last_seen"],
            "Severity": incident["combined_severity"],
            "Source risk": f"{incident.get('risk_score', 'n/a')}/100 {incident.get('risk_band', '')}",
            "Rules": ", ".join(incident["contributing_rules"]),
            "Attempts": incident.get("attempt_count", "n/a"),
            "Usernames": ", ".join(incident.get("usernames_targeted", [])) or "n/a",
            "Auth methods": ", ".join(incident.get("authentication_methods", []))
            or "Not available in parsed events",
        }
        for incident in visible_incidents
    ]
    st.dataframe(incident_rows, width="stretch", height=240, hide_index=True)
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
            f"{html.escape(str(incident['first_seen']))} – {html.escape(str(incident['last_seen']))} UTC"
        )
        st.write(incident["summary"])
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
        try:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            figure, axis = plt.subplots(figsize=(10, 3.5), constrained_layout=True)
            axis.plot(list(hourly), list(hourly.values()), marker="o", color="#48a9a6")
            axis.set_xlabel("Timestamp (UTC hour)")
            axis.set_ylabel("Failed attempts")
            if log_scale:
                axis.set_yscale("log")
            st.pyplot(figure)
            plt.close(figure)

            by_source: dict[str, Counter[datetime]] = defaultdict(Counter)
            for event in chart_events:
                failed = event.get("event_type") == "authentication_failure" or event.get(
                    "status"
                ) in (401, 403, 404)
                if not failed or not event.get("source_ip"):
                    continue
                stamp = _as_datetime(event.get("timestamp"))
                if stamp is not None:
                    hour = stamp.replace(minute=0, second=0, microsecond=0)
                    weight = event.get("occurrence_count", 1)
                    by_source[event["source_ip"]][hour] += (
                        weight if isinstance(weight, int) and weight > 0 else 1
                    )
            top_ips = [
                ip
                for ip, _ in sorted(
                    by_source.items(), key=lambda pair: (-sum(pair[1].values()), pair[0])
                )[:5]
            ]
            if top_ips:
                figure, axis = plt.subplots(figsize=(10, 4), constrained_layout=True)
                for ip in top_ips:
                    axis.plot(
                        sorted(by_source[ip]),
                        [by_source[ip][hour] for hour in sorted(by_source[ip])],
                        marker=".",
                        label=ip,
                    )
                axis.set_xlabel("Timestamp (UTC hour)")
                axis.set_ylabel("Failed attempts")
                axis.legend(loc="best")
                st.pyplot(figure)
                plt.close(figure)
        except ImportError:
            st.line_chart(
                {"timestamp": list(hourly), "failed_attempts": list(hourly.values())},
                x="timestamp",
                y="failed_attempts",
            )
    else:
        st.info("No timestamped failed attempts are available for the current filters.")

    st.subheader("Top source IPs and risk")
    risk_rows = [
        {"Source IP": ip, "Risk score": risk["score"], "Risk band": risk_band_badge(risk["band"])}
        for ip, risk in list(visible_risks.items())[:10]
    ]
    st.dataframe(
        [
            {**row, "Risk band": row["Risk band"].replace("<", "&lt;").replace(">", "&gt;")}
            for row in risk_rows
        ],
        width="stretch",
        hide_index=True,
    )

    username_rows, root_counts = _root_and_username_summary(visible_events)
    st.subheader("Username and root-login analytics")
    st.dataframe(username_rows, width="stretch", hide_index=True)
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
    csv_payload = render_csv(visible_alerts)
    from html_report import render_html_report

    html_payload = render_html_report(visible_events, visible_result)
    download_columns = st.columns(3)
    download_columns[0].download_button(
        "Download filtered JSON", payload, file_name="alerts.json", mime="application/json"
    )
    download_columns[1].download_button(
        "Download filtered CSV", csv_payload, file_name="alerts.csv", mime="text/csv"
    )
    download_columns[2].download_button(
        "Download filtered HTML", html_payload, file_name="report.html", mime="text/html"
    )


def main() -> None:
    """Start the local Streamlit dashboard with telemetry disabled."""
    os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
    import streamlit as st

    _render_dashboard(st)


if __name__ == "__main__":
    main()
