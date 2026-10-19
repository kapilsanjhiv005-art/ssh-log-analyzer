"""Local Streamlit dashboard for authorized SSH and web log analysis."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer import VERSION, _output_value, load_input
from config import load_config
from detections import analyze_events

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
            timestamp = event["timestamp"]
            if not isinstance(timestamp, datetime):
                timestamp = datetime.fromisoformat(timestamp)
            counts[timestamp.replace(minute=0, second=0, microsecond=0)] += 1
    return dict(sorted(counts.items()))


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
        threshold = st.slider("Key detection threshold", 1, 50, default_threshold)
        window_seconds = st.slider("Detection window (seconds)", 1, 3600, 60)
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
    """Analyze a selected local file and display summary, tables, and JSON."""
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

    counts = Counter(alert["severity"] for alert in result["alerts"])
    columns = st.columns(4)
    for column, severity in zip(columns, SEVERITIES):
        column.metric(severity, counts.get(severity, 0))

    st.subheader("Alerts")
    selected_severity = st.multiselect("Filter by severity", SEVERITIES, default=list(SEVERITIES))
    visible = [alert for alert in result["alerts"] if alert["severity"] in selected_severity]
    alert_rows = [
        {
            "Rule": html.escape(str(alert["rule"]), quote=True),
            "Base severity": html.escape(
                str(alert.get("base_severity", alert["severity"])), quote=True
            ),
            "Source IP": html.escape(str(alert["source_ip"]), quote=True),
            "First seen": html.escape(str(alert["first_seen"]), quote=True),
            "Last seen": html.escape(str(alert["last_seen"]), quote=True),
            "Attempts": alert["attempt_count"],
            "Source risk score (composite)": alert.get(
                "source_risk_score", alert.get("risk_score")
            ),
            "Source risk band (composite)": alert.get("source_risk_band", alert.get("risk_band")),
            "Details": html.escape(alert["description"]),
        }
        for alert in visible
    ]
    st.dataframe(alert_rows, width="stretch", hide_index=True)

    st.subheader("Failed attempts over time")
    hourly = _attempts_by_hour(events)
    chart_data = {
        "timestamp": [stamp for stamp in hourly],
        "failed_attempts": list(hourly.values()),
    }
    st.line_chart(chart_data, x="timestamp", y="failed_attempts")

    st.subheader("Top source IPs and risk")
    risk_rows = (
        "".join(
            "<tr>"
            f"<td>{html.escape(ip, quote=True)}</td>"
            f"<td>{risk['score']}/100</td>"
            f"<td>{risk_band_badge(risk['band'])}</td>"
            "</tr>"
            for ip, risk in list(result["risk_scores"].items())[:10]
        )
        or '<tr><td colspan="3">No source IPs.</td></tr>'
    )
    st.markdown(
        "<table><thead><tr><th>Source IP</th><th>Risk score</th><th>Band</th></tr></thead>"
        f"<tbody>{risk_rows}</tbody></table>",
        unsafe_allow_html=True,
    )

    st.subheader("Incident drill-down")
    incidents = result["incidents"]
    if incidents:
        selected_incident = st.selectbox(
            "Select incident",
            incidents,
            format_func=lambda incident: (
                f"{incident['incident_id']} · {incident['combined_severity']} · "
                f"{incident['source_ip']}"
            ),
        )
        st.json(_output_value(selected_incident))
    else:
        st.info("No correlated incidents.")

    st.subheader("Parser coverage")
    st.json(parse_stats)
    payload = json.dumps(_output_value(result), indent=2, ensure_ascii=False)
    st.download_button(
        "Download JSON report", payload, file_name="alerts.json", mime="application/json"
    )


def main() -> None:
    """Start the local Streamlit dashboard with telemetry disabled."""
    os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
    import streamlit as st

    _render_dashboard(st)


if __name__ == "__main__":
    main()
