"""Tests for the dashboard's shared analysis helper."""

import logging
import tomllib
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

from analyzer import render_csv
from dashboard import (
    _brand_asset_for_page,
    _dashboard_theme_css,
    _detailed_attempts_chart,
    _detailed_source_activity_chart,
    _overview_attempts_chart,
    _timeline_chart,
    _top_sources_chart,
    analyze_for_dashboard,
    dashboard_markdown_without_links,
    data_quality_metrics,
    data_quality_sections,
    detection_inventory_rows,
    filter_dashboard_data,
    filter_timeline_events,
    malformed_summary_rows,
    related_activity_rows,
    risk_band_badge,
    settings_sections,
    source_outcome_counts,
    source_risk_rows,
    summarize_dashboard_metrics,
    timeline_event_rows,
    timeline_selection_bounds,
)
from detections import analyze_events
from html_report import render_html_report


def test_dashboard_risk_badge_uses_supported_color_and_plain_label():
    badge = risk_band_badge("Critical")
    assert badge == {"label": "Critical", "color": "red"}
    assert risk_band_badge("<script>") == {"label": "Unknown", "color": "gray"}


def test_dashboard_malformed_summary_is_sorted_and_uses_reason_counts():
    assert malformed_summary_rows(
        {"malformed_by_reason": {"invalid_timestamp": 2, "invalid_ip": 1}}
    ) == [{"Reason": "invalid_ip", "Lines": 1}, {"Reason": "invalid_timestamp", "Lines": 2}]


def test_data_quality_metrics_distinguish_records_from_weighted_occurrences():
    metrics = data_quality_metrics(
        {
            "lines_read": 4,
            "events_parsed": 3,
            "effective_event_occurrences": 8,
            "lines_ignored": 1,
            "lines_malformed": 0,
        },
        [{"occurrence_count": 8}],
    )

    assert metrics == [
        ("Lines read", 4),
        ("Parsed records", 3),
        ("Effective occurrences", 8),
        ("Ignored", 1),
        ("Malformed", 0),
        ("Malformed rate", "0.0%"),
    ]


def test_detection_inventory_display_does_not_create_dead_local_doc_links():
    markdown = "See [`evaluation.md`](evaluation.md) and [external](https://example.test)."

    rendered_source = dashboard_markdown_without_links(markdown)

    assert "evaluation.md" in rendered_source
    assert "[evaluation.md](" not in rendered_source
    assert "https://example.test" not in rendered_source


def test_dashboard_theme_is_local_and_uses_semantic_metric_styles():
    css = _dashboard_theme_css()

    assert "--sentinel-teal: #35e0c1" in css
    assert "st-key-kpi-critical" in css
    assert "st-key-kpi-good" in css
    assert "@media (max-width: 768px)" in css
    assert "padding: 2.8rem .8rem 1.5rem" in css
    assert "--sentinel-background: #070b16" in css
    assert "prefers-reduced-motion" in css
    assert "url(http" not in css.casefold()


def test_dashboard_theme_uses_high_contrast_navy_sidebar_and_clear_states():
    css = _dashboard_theme_css()

    assert "#0b1120" in css
    assert 'aria-current="page"' in css
    assert ":focus-visible" in css
    assert "#35e0c1" in css.casefold()

    theme = tomllib.loads(
        (Path(__file__).resolve().parents[1] / ".streamlit" / "config.toml").read_text(
            encoding="utf-8"
        )
    )["theme"]
    assert theme["base"] == "dark"
    assert theme["backgroundColor"] == "#070b16"
    assert theme["dataframeHeaderBackgroundColor"] == "#17253d"


def test_source_risk_rows_are_compact_and_keep_score_band_and_outcomes_distinct():
    rows = source_risk_rows(
        {"192.0.2.4": {"score": 81, "band": "Critical"}},
        [
            {
                "timestamp": datetime(2026, 10, 19, 9),
                "source_ip": "192.0.2.4",
                "event_type": "authentication_failure",
                "occurrence_count": 3,
            },
            {
                "timestamp": datetime(2026, 10, 19, 10),
                "source_ip": "192.0.2.4",
                "event_type": "authentication_success",
                "occurrence_count": 1,
            },
        ],
        [{"source_ip": "192.0.2.4", "attempt_count": 3}],
        [{"source_ip": "192.0.2.4"}],
        log_type="ssh",
    )

    assert rows == [
        {
            "Source IP": "192.0.2.4",
            "Risk score": 81,
            "Risk band": "Critical",
            "Alerts": 1,
            "Incidents": 1,
            "First seen (parsed timestamp)": datetime(2026, 10, 19, 9),
            "Last seen (parsed timestamp)": datetime(2026, 10, 19, 10),
            "Failed SSH attempts": 3,
            "Successful SSH attempts": 1,
        }
    ]


def test_source_investigation_root_746_count_does_not_leak_from_global_summary():
    """Keep the reported global root-count bug inside the selected source scope."""
    from dashboard import source_investigation_summary

    events = [
        {
            "source_ip": "183.62.140.253",
            "event_type": "authentication_failure",
            "username": "analyst",
            "occurrence_count": 2,
        },
        {
            "source_ip": "198.51.100.74",
            "event_type": "authentication_failure",
            "username": "root",
            "occurrence_count": 746,
        },
        {
            "source_ip": "198.51.100.74",
            "event_type": "authentication_failure",
            "username": "other-user",
            "occurrence_count": 38,
        },
        {
            "source_ip": "198.51.100.74",
            "event_type": "session_opened",
            "username": "unrelated-session-user",
            "occurrence_count": 1,
        },
    ]

    summary = source_investigation_summary(events, "183.62.140.253")

    assert summary["failed_attempts"] == 2
    assert summary["username_rows"] == [{"Username": "analyst", "Failed attempts": 2}]
    assert summary["root_counts"] == {"failed": 0, "successful": 0}
    assert summary["events"] == [events[0]]


def test_incident_investigation_timeline_uses_only_incident_evidence_ids():
    from dashboard import incident_evidence_events

    selected = {
        "_event_id": "ssh:2",
        "source_ip": "192.0.2.10",
        "event_type": "authentication_failure",
    }
    unrelated_same_source_and_window = {
        "_event_id": "ssh:3",
        "source_ip": "192.0.2.10",
        "event_type": "authentication_success",
    }
    other_source = {
        "_event_id": "ssh:4",
        "source_ip": "198.51.100.4",
        "event_type": "authentication_failure",
    }
    linked_context = {
        "_event_id": "ssh:1",
        "source_ip": None,
        "event_type": "authentication_context",
    }

    rows = incident_evidence_events(
        [selected, unrelated_same_source_and_window, other_source, linked_context],
        {"evidence_event_ids": ["ssh:1", "ssh:2"]},
    )

    assert rows == [selected, linked_context]


def test_data_quality_sections_separate_input_event_auth_and_health_metrics():
    sections = data_quality_sections(
        {
            "lines_read": 5,
            "events_parsed": 3,
            "lines_ignored": 1,
            "lines_malformed": 1,
            "effective_event_occurrences": 7,
            "authentication_failures": 4,
            "password_authentication_failures": 3,
            "authentication_method_probes": 1,
            "authentication_successes": 1,
            "root_authentication_failures": 2,
            "root_password_authentication_failures": 2,
            "root_authentication_successes": 0,
            "effective_authentication_attempts": 5,
            "authentication_context_records": 2,
            "supporting_evidence_records": 1,
            "unattributed_contextual_records": 1,
            "unresolved_or_ambiguous_context_records": 1,
            "malformed_by_reason": {"invalid_timestamp": 1},
            "authentication_context_categories": {
                "invalid_user": 1,
                "pam_authentication_failure": 1,
            },
            "parsed_record_categories": {
                "connection_closed": 2,
                "identification_missing": 1,
            },
        },
        [{"occurrence_count": 7}],
        log_type="ssh",
    )

    assert [name for name, _ in sections] == [
        "Input accounting",
        "Event accounting",
        "Authentication attempts",
        "SSH context and probes",
        "Parser health",
    ]
    assert dict(sections[0][1]) == {
        "Lines read": 5,
        "Parsed records": 3,
        "Ignored lines": 1,
        "Malformed lines": 1,
    }
    assert dict(sections[1][1]) == {"Effective occurrences": 7}
    assert dict(sections[2][1])["Failed authentication attempts (all methods)"] == 4
    assert dict(sections[2][1])["Failed password attempts"] == 3
    assert dict(sections[2][1])["Authentication-method probes (Failed none)"] == 1
    assert dict(sections[2][1])["Terminal authentication attempts"] == 5
    assert dict(sections[2][1])["Unresolved or ambiguous context records"] == 1
    context_categories = dict(sections[3][1])
    assert context_categories["Invalid-user context records"] == 1
    assert context_categories["PAM authentication-failure context records"] == 1
    assert context_categories["Connection-closed records"] == 2
    assert context_categories["Identification-missing records"] == 1
    assert "invalid_timestamp: 1" in dict(sections[4][1])["Malformed reasons"]


def test_web_data_quality_does_not_label_http_outcomes_as_authentication():
    sections = data_quality_sections(
        {
            "lines_read": 2,
            "events_parsed": 2,
            "lines_ignored": 0,
            "lines_malformed": 0,
            "effective_event_occurrences": 2,
        },
        [{"status": 401}, {"status": 200}],
        log_type="web",
    )

    assert [name for name, _ in sections] == [
        "Input accounting",
        "Event accounting",
        "Parser health",
    ]
    assert all("Authentication" not in name for name, _ in sections)


def test_detection_inventory_is_structured_and_keeps_test_refs_secondary():
    inventory = (Path(__file__).resolve().parents[1] / "docs" / "detection-inventory.md").read_text(
        encoding="utf-8"
    )

    rows = detection_inventory_rows(inventory)
    brute_force = next(row for row in rows if row["Rule"] == "ssh_brute_force")

    assert brute_force["Detection"] == "repeated SSH failures from one source"
    assert "5 weighted failures" in brute_force["Threshold/window"]
    assert brute_force["MITRE ATT&CK"] == "T1110.001, Password Guessing"
    assert "tests/test_detections.py" in brute_force["Test references"]
    assert len(rows) >= 10


def test_detection_summary_rows_keep_the_primary_table_compact():
    from dashboard import detection_summary_rows

    rows = detection_summary_rows(
        [
            {
                "Rule": "ssh_brute_force",
                "Detection": "repeated SSH failures from one source",
                "Severity": "Medium; High above threshold",
                "MITRE ATT&CK": "T1110.001, Password Guessing",
                "Test references": "tests/test_detections.py::test_brute_force",
            }
        ]
    )

    assert rows == [
        {
            "Rule ID": "ssh_brute_force",
            "Detection": "repeated SSH failures from one source",
            "Base severity": "Medium",
        }
    ]


def test_settings_value_rows_are_compact_and_preserve_actual_values():
    from dashboard import settings_value_rows

    rows = settings_value_rows(
        [
            ("threshold", 5),
            ("window_seconds", 60),
            ("enabled", False),
            ("login_paths", ["/login", "/admin"]),
        ]
    )

    assert rows == [
        {"Setting": "Threshold", "Configured value": "5"},
        {"Setting": "Window seconds", "Configured value": "60"},
        {"Setting": "Enabled", "Configured value": "False"},
        {"Setting": "Login paths", "Configured value": "/login, /admin"},
    ]


def test_original_sparkle_asset_is_used_for_branding():
    from dashboard import PROJECT_DIR

    asset = _brand_asset_for_page("Overview")
    assert asset == PROJECT_DIR / "sentinel-sparkle.svg"
    assert asset.is_file()
    assert "linearGradient" in asset.read_text(encoding="utf-8")


def test_dashboard_table_renderer_applies_shared_native_defaults():
    from dashboard import render_dashboard_table

    class TableSpy:
        def dataframe(self, data, **kwargs):
            self.data = data
            self.kwargs = kwargs

    spy = TableSpy()
    data = [{"Rule": "ssh_brute_force"}]
    render_dashboard_table(spy, data)

    assert spy.data == data
    assert spy.kwargs["width"] == "stretch"
    assert spy.kwargs["hide_index"] is True


def test_shared_dataframe_theme_uses_white_text_on_navy_for_main_and_sidebar():
    import tomllib

    from dashboard import PROJECT_DIR

    theme = tomllib.loads((PROJECT_DIR / ".streamlit" / "config.toml").read_text())["theme"]

    assert theme["dataframeHeaderBackgroundColor"] == "#17253d"
    assert theme["dataframeHeaderTextColor"] == "#ffffff"
    assert theme["sidebar"]["dataframeHeaderBackgroundColor"] == "#17253d"
    assert theme["sidebar"]["dataframeHeaderTextColor"] == "#ffffff"


def test_alert_detail_summary_preserves_rule_and_source_risk_distinctions():
    from dashboard import alert_detail_summary

    alert = {
        "rule": "ssh_brute_force",
        "base_severity": "Medium",
        "severity": "Medium",
        "source_ip": "192.0.2.25",
        "attempt_count": 8,
        "first_seen": "2026-10-20T08:00:00",
        "last_seen": "2026-10-20T08:00:30",
        "description": "Eight failures.",
        "recommended_action": "Review the source.",
        "source_risk_score": 77,
        "source_risk_band": "Critical",
    }

    summary = alert_detail_summary(alert)

    assert summary["Rule-level severity"] == "Medium"
    assert summary["Source risk"] == "77/100 · Critical"
    assert summary["Attempts"] == 8
    assert alert["severity"] == "Medium"


def test_detection_coverage_page_has_analyst_table_and_secondary_traceability():
    from streamlit.testing.v1 import AppTest

    script = """\
import streamlit as st
import dashboard
stats = {"lines_read": 0, "events_parsed": 0}
result = dashboard.analyze_events([])
context = dashboard._dashboard_page_context([], stats, result)
dashboard._render_soc_page(st, "Detection Coverage", context)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    assert len(app.dataframe) == 1
    assert any(
        "Synthetic tests do not establish real-world accuracy." in item.value
        for item in app.caption
    )


def test_settings_page_renders_grouped_values_and_session_scope():
    from streamlit.testing.v1 import AppTest

    script = """\
import streamlit as st
import dashboard
config = dashboard.load_config(dashboard.PROJECT_DIR / "config.yaml")
events, stats, result = dashboard.analyze_for_dashboard(
    dashboard.SAMPLE_LOGS["SSH sample"], log_type="ssh", year=2026, config=config
)
context = dashboard._dashboard_page_context(events, stats, result)
context.update({"log_type": "SSH", "year": 2026, "allowlist_enabled": False})
dashboard._render_soc_page(st, "Settings", context)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    rendered = "\n".join(item.label for item in app.expander)
    assert all(
        title in rendered
        for title in (
            "SSH brute force",
            "Low-and-slow SSH",
            "Multi-account guessing",
            "Web detections",
        )
    )
    assert any("do not update config.yaml" in item.value for item in app.caption)
    assert any("timezone-unspecified" in item.value for item in app.caption)
    assert any("normalized to UTC" in item.value for item in app.caption)


def test_settings_sections_reflect_current_config_without_mutating_it():
    from config import load_config

    config = load_config(Path(__file__).resolve().parents[1] / "config.yaml")
    before = repr(config)
    groups = settings_sections(config)

    assert [name for name, _ in groups] == [
        "SSH brute force",
        "Low-and-slow SSH",
        "Multi-account guessing",
        "Invalid-user probing",
        "Distributed brute force",
        "Root authentication",
        "Success after failures",
        "New-source policy",
        "Alert merging",
        "Severity escalation",
        "Business hours",
        "Web detections",
    ]
    assert dict(groups[0][1])["threshold"] == 5
    assert repr(config) == before


def test_dashboard_analysis_uses_shared_web_pipeline_and_allowlist(tmp_path):
    log = tmp_path / "access.log"
    row = '192.0.2.7 - - [19/Oct/2026:08:00:00 +0000] "POST /login HTTP/1.1" 401 12 "-" "Browser"'
    log.write_text("\n".join([row] * 5) + "\n", encoding="utf-8")

    events, stats, result = analyze_for_dashboard(
        log,
        log_type="web",
        year=2026,
        allowlist_text="# trusted test source\n192.0.2.0/24\n",
    )

    assert len(events) == 5
    assert events[0]["timestamp"] == datetime(2026, 10, 19, 8)
    assert stats["events_parsed"] == 5
    assert result["alerts"] == []
    assert result["alerts_suppressed"] == 1
    assert result["timestamp_interpretation"]["year_for_yearless_timestamps"] is None
    assert (
        "Explicit offsets are normalized to UTC"
        in result["timestamp_interpretation"]["offset_timestamp_policy"]
    )


def test_dashboard_analysis_respects_threshold_and_reports_shared_alert(tmp_path):
    log = tmp_path / "access.log"
    row = '192.0.2.7 - - [19/Oct/2026:08:00:00 +0000] "POST /login HTTP/1.1" 401 12 "-" "Browser"'
    log.write_text("\n".join([row] * 5) + "\n", encoding="utf-8")

    _, _, result = analyze_for_dashboard(log, log_type="web", year=2026, threshold=5)

    assert result["alerts"][0]["rule"] == "web_login_bruteforce"
    assert result["alerts"][0]["mitre_attack_id"] is None
    assert "do not prove authentication attempts" in result["alerts"][0]["mitre_mapping_note"]


def test_dashboard_analysis_includes_reason_counts_and_only_line_numbers(tmp_path):
    log = tmp_path / "malformed.log"
    log.write_text(
        "Oct 19 09:00:00 host sshd[1]: Failed password for user from nowhere\n",
        encoding="utf-8",
    )

    _, stats, _ = analyze_for_dashboard(log, log_type="ssh", year=2026)

    assert stats["malformed_by_reason"] == {"invalid_source_ip": 1}
    assert stats["malformed_records"] == [{"line_number": 1, "reason": "invalid_source_ip"}]


def test_dashboard_new_source_rule_requires_an_explicit_allowlist(tmp_path):
    log = tmp_path / "successful-login.log"
    log.write_text(
        "Oct 19 09:00:00 host sshd[1]: Accepted password for analyst "
        "from 198.51.100.44 port 22 ssh2\n",
        encoding="utf-8",
    )

    _, _, no_allowlist = analyze_for_dashboard(log, log_type="ssh", year=2026)
    _, _, explicitly_empty = analyze_for_dashboard(
        log, log_type="ssh", year=2026, allowlist_text="# no source is trusted yet\n"
    )

    assert not any(alert["rule"] == "ssh_new_source_ip_login" for alert in no_allowlist["alerts"])
    assert any(alert["rule"] == "ssh_new_source_ip_login" for alert in explicitly_empty["alerts"])


def test_dashboard_metrics_separate_rule_severity_from_unique_source_risk():
    alerts = [
        {"severity": "Critical", "base_severity": "Low", "source_ip": "192.0.2.10"},
        {"severity": "Medium", "base_severity": "Medium", "source_ip": "192.0.2.10"},
    ]
    metrics = summarize_dashboard_metrics(
        alerts, {"192.0.2.10": {"score": 86, "band": "Critical"}}, []
    )

    assert metrics["critical_alerts"] == 0
    assert metrics["low_alerts"] == 1
    assert metrics["medium_alerts"] == 1
    assert metrics["critical_risk_sources"] == 1


def test_dashboard_metrics_are_zero_for_empty_analysis():
    metrics = summarize_dashboard_metrics([], {}, [])
    assert all(value == 0 for value in metrics.values())


def test_streamlit_dashboard_starts_on_overview_without_page_errors():
    from streamlit.testing.v1 import AppTest

    script = Path(__file__).resolve().parents[1] / "dashboard.py"
    app = AppTest.from_file(str(script)).run(timeout=20)

    assert not app.exception
    assert [title.value for title in app.title][-1] == "Security Operations Overview"
    assert {metric.label for metric in app.metric} >= {
        "Critical alerts",
        "Incidents",
        "Critical-risk IPs",
    }
    assert any(
        "Source and parsed-time date filters scope events" in item.value for item in app.caption
    )


def test_global_clear_filters_restores_all_source_and_severity_defaults():
    from streamlit.testing.v1 import AppTest

    script = Path(__file__).resolve().parents[1] / "dashboard.py"
    app = AppTest.from_file(str(script)).run(timeout=20)
    sources = app.selectbox(key="global_source_ip").options
    assert len(sources) > 1

    app.selectbox(key="global_source_ip").select(sources[1]).run(timeout=20)
    assert app.selectbox(key="global_source_ip").value == sources[1]

    app.button(key="clear_global_filters").click().run(timeout=20)

    assert app.selectbox(key="global_source_ip").value == "All sources"
    assert app.multiselect(key="global_severity").value == ["Critical", "High", "Medium", "Low"]


def test_data_dependent_filter_state_does_not_conflict_with_widget_defaults(caplog):
    from streamlit.testing.v1 import AppTest

    script = Path(__file__).resolve().parents[1] / "dashboard.py"
    with caplog.at_level(logging.WARNING):
        app = AppTest.from_file(str(script)).run(timeout=20)

    assert not any(
        "created with a default value but also had its value set via the Session State API"
        in record.message
        for record in caplog.records
    )
    assert app.multiselect(key="global_rules").value == app.multiselect(key="global_rules").options
    assert (
        app.multiselect(key="global_usernames").value
        == app.multiselect(key="global_usernames").options
    )


def test_changing_log_type_resets_stale_rule_and_username_filters():
    from streamlit.testing.v1 import AppTest

    script = Path(__file__).resolve().parents[1] / "dashboard.py"
    app = AppTest.from_file(str(script)).run(timeout=20)
    ssh_rules = app.multiselect(key="global_rules").options
    ssh_users = app.multiselect(key="global_usernames").options
    assert ssh_rules and ssh_users

    app.multiselect(key="global_rules").select(ssh_rules[0]).run(timeout=20)
    app.multiselect(key="global_usernames").select(ssh_users[0]).run(timeout=20)
    app.selectbox[0].select("web").run(timeout=20)

    assert app.selectbox[0].value == "web"
    assert app.multiselect(key="global_rules").value == app.multiselect(key="global_rules").options
    assert all(rule.startswith("web_") for rule in app.multiselect(key="global_rules").value)
    assert all(
        user in app.multiselect(key="global_usernames").options
        for user in app.multiselect(key="global_usernames").value
    )
    assert sum(int(metric.value) for metric in app.metric if metric.label.endswith("alerts")) > 0


@pytest.mark.parametrize(
    "page_name",
    (
        "Alerts",
        "Timeline",
        "Detection Coverage",
        "Data Quality",
        "Sources",
        "Incidents",
        "Reports",
        "Settings",
    ),
)
def test_soc_pages_render_bundled_sample_without_errors(page_name):
    from streamlit.testing.v1 import AppTest

    script = f"""\
import streamlit as st
import dashboard
events, stats, result = dashboard.analyze_for_dashboard(
    dashboard.SAMPLE_LOGS["SSH sample"], log_type="ssh", year=2026
)
context = dashboard._dashboard_page_context(events, stats, result)
dashboard._render_soc_page(st, {page_name!r}, context)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    from dashboard import PAGE_DISPLAY_NAMES

    assert PAGE_DISPLAY_NAMES[page_name] in [item.value for item in app.title]
    if page_name == "Data Quality":
        assert any(metric.label == "Effective occurrences" for metric in app.metric)


@pytest.mark.parametrize(
    "page_name",
    (
        "Overview",
        "Alerts",
        "Incidents",
        "Sources",
        "Timeline",
        "Detection Coverage",
        "Data Quality",
        "Reports",
        "Settings",
    ),
)
def test_soc_pages_render_empty_analysis_without_errors(page_name):
    from streamlit.testing.v1 import AppTest

    script = f"""\
import streamlit as st
import dashboard
stats = {{"lines_read": 0, "events_parsed": 0, "lines_ignored": 0, "lines_malformed": 0}}
result = dashboard.analyze_events([])
context = dashboard._dashboard_page_context([], stats, result)
dashboard._render_soc_page(st, {page_name!r}, context)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    from dashboard import PAGE_DISPLAY_NAMES

    assert PAGE_DISPLAY_NAMES[page_name] in [item.value for item in app.title]


def test_detailed_analysis_renders_bundled_sample_without_errors():
    from streamlit.testing.v1 import AppTest

    script = """\
import streamlit as st
import dashboard
config = dashboard.load_config(dashboard.PROJECT_DIR / "config.yaml")
events, stats, result = dashboard.analyze_for_dashboard(
    dashboard.SAMPLE_LOGS["SSH sample"], log_type="ssh", year=2026, config=config
)
dashboard._show_analysis(
    st, dashboard.SAMPLE_LOGS["SSH sample"], "ssh", 2026, config, "", 5, 60,
    preloaded=(events, stats, result),
)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    assert any(item.value == "Detailed Analysis" for item in app.title)


def test_dashboard_filter_uses_source_and_inclusive_date_without_mutation():
    start = datetime(2026, 10, 19, 8)
    events = [
        {"timestamp": start, "source_ip": "192.0.2.10", "event_type": "authentication_failure"},
        {
            "timestamp": start + timedelta(days=1),
            "source_ip": "192.0.2.11",
            "event_type": "authentication_failure",
        },
    ]
    result = analyze_events(events)

    filtered_events, filtered_result = filter_dashboard_data(
        events,
        result,
        source_ip="192.0.2.10",
        start_date=date(2026, 10, 19),
        end_date=date(2026, 10, 19),
    )

    assert len(filtered_events) == 1
    assert set(filtered_result["risk_scores"]) == {"192.0.2.10"}
    assert len(events) == 2


def test_dashboard_filter_handles_empty_range():
    filtered_events, filtered_result = filter_dashboard_data(
        [],
        {"alerts": [], "risk_scores": {}, "incidents": []},
        start_date=date(2026, 10, 19),
        end_date=date(2026, 10, 19),
    )
    assert filtered_events == []
    assert filtered_result["risk_scores"] == {}
    assert filtered_result["incidents"] == []


def test_dashboard_alert_filters_apply_rules_usernames_and_search_consistently():
    start = datetime(2026, 10, 19, 9)
    events = [
        {
            "timestamp": start + timedelta(seconds=second),
            "source_ip": "192.0.2.55",
            "username": "root",
            "event_type": "authentication_failure",
            "occurrence_count": 1,
        }
        for second in range(5)
    ]
    result = analyze_events(events)

    _, filtered = filter_dashboard_data(
        events,
        result,
        rules={"ssh_root_login_attempt"},
        usernames={"root"},
        search_query="root_login",
    )

    assert [alert["rule"] for alert in filtered["alerts"]] == ["ssh_root_login_attempt"]
    assert filtered["incidents"] == []
    assert set(filtered["risk_scores"]) == {"192.0.2.55"}


def test_dashboard_timeline_rows_are_chronological_and_label_unlinked_context():
    later = datetime(2026, 10, 19, 9, 5)
    earlier = later - timedelta(minutes=5)
    rows = timeline_event_rows(
        [
            {
                "timestamp": later,
                "source_ip": "192.0.2.8",
                "event_type": "authentication_failure",
                "username": "analyst",
                "occurrence_count": 3,
            },
            {
                "timestamp": earlier,
                "source_ip": None,
                "event_type": "session_opened",
                "username": "analyst",
                "occurrence_count": 1,
            },
        ]
    )

    assert [row["Event"] for row in rows] == ["session_opened", "authentication_failure"]
    assert rows[0]["Linkage"] == "Unlinked context"
    assert rows[0]["Source IP"] is None
    assert rows[1]["Occurrences"] == 3


def test_source_outcome_counts_use_weights_and_do_not_call_web_responses_authentication():
    ssh_counts = source_outcome_counts(
        [
            {"event_type": "authentication_failure", "occurrence_count": 4},
            {"event_type": "authentication_success", "occurrence_count": 2},
            {"event_type": "session_opened", "occurrence_count": 1},
        ],
        log_type="ssh",
    )
    web_counts = source_outcome_counts(
        [
            {"status": 401, "occurrence_count": 3},
            {"status": 200, "occurrence_count": 2},
        ],
        log_type="web",
    )

    assert ssh_counts == ("Failed SSH", 4, "Successful SSH", 2)
    assert web_counts == (
        "Unauthorized/not-found responses",
        3,
        "2xx responses (not auth success)",
        2,
    )


def test_timeline_interval_selection_accepts_valid_bounds_and_ignores_empty_values():
    bounds = timeline_selection_bounds(
        {"timeline_brush": {"hour": ["2026-10-19T09:00:00", "2026-10-19T10:00:00"]}}
    )

    assert bounds == (datetime(2026, 10, 19, 9), datetime(2026, 10, 19, 10))
    assert [
        row["event_type"]
        for row in filter_timeline_events(
            [
                {"timestamp": datetime(2026, 10, 19, 9), "event_type": "inside"},
                {"timestamp": datetime(2026, 10, 19, 10, 1), "event_type": "outside"},
            ],
            bounds,
        )
    ] == ["inside"]
    assert timeline_selection_bounds({"timeline_brush": {}}) is None


def test_timeline_brush_epoch_milliseconds_are_interpreted_as_utc():
    bounds = timeline_selection_bounds({"timeline_brush": {"hour": [1792400400000, 1792404000000]}})

    assert bounds == (datetime(2026, 10, 19, 9), datetime(2026, 10, 19, 10))


def test_timeline_brush_bounds_filter_events_inclusively_and_ignore_bad_timestamps():
    bounds = timeline_selection_bounds(
        {"timeline_brush": {"hour": ["2026-10-19T09:00:00", "2026-10-19T10:00:00"]}}
    )
    events = [
        {"timestamp": datetime(2026, 10, 19, 8, 59, 59), "event_type": "before"},
        {"timestamp": datetime(2026, 10, 19, 9), "event_type": "start"},
        {"timestamp": datetime(2026, 10, 19, 10), "event_type": "end"},
        {"timestamp": "not-a-timestamp", "event_type": "malformed"},
    ]

    assert [event["event_type"] for event in filter_timeline_events(events, bounds)] == [
        "start",
        "end",
    ]


def test_timeline_chart_serializes_datetime_values_as_utc_iso_strings():
    stamp = datetime(2026, 10, 19, 9)
    chart = _timeline_chart(
        [
            {
                "timestamp": stamp,
                "event_type": "authentication_failure",
                "occurrence_count": 2,
            }
        ]
    )

    assert chart is not None
    assert chart.to_dict()["data"]["values"] == [
        {
            "hour": "2026-10-19T09:00:00Z",
            "hour_label": "2026-10-19 09:00",
            "failed_attempts": 2,
        }
    ]
    assert chart.to_dict()["encoding"]["x"]["axis"]["formatType"] == "utc"
    assert (
        chart.to_dict()["encoding"]["x"]["axis"]["labelExpr"]
        == "utcFormat(datum.value, '%Y-%m-%d %H:%M')"
    )


def test_overview_charts_use_weighted_events_and_risk_scores():
    stamp = datetime(2026, 10, 19, 9, 15)
    events = [
        {
            "timestamp": stamp,
            "event_type": "authentication_failure",
            "occurrence_count": 4,
        },
        {
            "timestamp": stamp + timedelta(minutes=20),
            "event_type": "authentication_success",
            "occurrence_count": 1,
        },
    ]

    attempts = _overview_attempts_chart(events).to_dict()
    sources = _top_sources_chart(
        {
            "192.0.2.9": {"score": 82, "band": "Critical"},
            "198.51.100.4": {"score": 35, "band": "Medium"},
        }
    ).to_dict()

    assert attempts["data"]["values"] == [{"hour": "2026-10-19T09:00:00Z", "failed_attempts": 4}]
    assert attempts["layer"][0]["encoding"]["x"]["title"] == "Time (parsed timestamp)"
    assert [item["source_ip"] for item in sources["data"]["values"]] == [
        "192.0.2.9",
        "198.51.100.4",
    ]
    assert sources["encoding"]["x"]["scale"]["domain"] == [0, 100]
    assert sources["encoding"]["y"]["axis"]["labelLimit"] == 320
    assert sources["config"]["axis"]["labelColor"] == "#a7b7cc"


def test_detailed_analysis_charts_are_interactive_and_preserve_weighted_counts():
    from datetime import timezone

    events = [
        {
            "timestamp": datetime(2026, 10, 20, 10, 5, tzinfo=timezone.utc),
            "source_ip": "192.0.2.20",
            "event_type": "authentication_failure",
            "occurrence_count": 3,
        },
        {
            "timestamp": datetime(2026, 10, 20, 10, 35, tzinfo=timezone.utc),
            "source_ip": "198.51.100.30",
            "event_type": "authentication_failure",
            "occurrence_count": 2,
        },
        {
            "timestamp": datetime(2026, 10, 20, 11, 5, tzinfo=timezone.utc),
            "source_ip": "203.0.113.40",
            "status": 404,
            "occurrence_count": 4,
        },
    ]

    attempts_chart = _detailed_attempts_chart(events)
    source_chart = _detailed_source_activity_chart(events)
    attempts_spec = attempts_chart.to_dict()
    source_spec = source_chart.to_dict()

    assert _detailed_attempts_chart([]) is None
    assert _detailed_source_activity_chart([]) is None
    assert [row["failed_attempts"] for row in attempts_spec["data"]["values"]] == [5, 4]
    assert {row["failed_attempts"] for row in source_spec["data"]["values"]} == {2, 3, 4}
    assert attempts_spec["params"][0]["select"]["type"] == "interval"
    assert source_spec["params"][0]["select"]["type"] == "interval"
    assert attempts_spec["params"][0]["bind"] == "scales"
    assert source_spec["encoding"]["color"]["field"] == "source_ip"
    assert source_spec["encoding"]["color"]["type"] == "nominal"


def test_related_activity_is_advisory_source_match_and_does_not_mutate_alerts():
    selected = {
        "rule": "ssh_brute_force",
        "severity": "Medium",
        "source_ip": "192.0.2.40",
        "source_ips": [],
        "first_seen": datetime(2026, 10, 20, 10),
    }
    same_source = {
        "rule": "ssh_root_login_attempt",
        "severity": "Low",
        "source_ip": "192.0.2.40",
        "first_seen": datetime(2026, 10, 20, 12),
    }
    unrelated = {
        "rule": "ssh_brute_force",
        "severity": "Medium",
        "source_ip": "198.51.100.40",
        "first_seen": datetime(2026, 10, 20, 10),
    }
    alerts = [selected, same_source, unrelated]
    original = [dict(item) for item in alerts]

    related = related_activity_rows(alerts, selected)

    assert related == [
        {
            "Rule": "ssh_root_login_attempt",
            "Severity": "Low",
            "Source IP": "192.0.2.40",
            "First seen (parsed timestamp)": datetime(2026, 10, 20, 12),
            "Why related": "Shares source IP 192.0.2.40",
        }
    ]
    assert alerts == original
    assert related_activity_rows([selected, unrelated], selected) == []


def test_related_activity_matches_documented_sources_for_distributed_alerts():
    selected = {
        "rule": "ssh_distributed_bruteforce",
        "source_ip": None,
        "source_ips": ["192.0.2.10", "198.51.100.10"],
    }
    candidate = {
        "rule": "ssh_brute_force",
        "source_ip": "198.51.100.10",
        "source_ips": [],
    }

    rows = related_activity_rows([selected, candidate], selected)

    assert rows[0]["Why related"] == "Shares source IP 198.51.100.10"


def test_severity_distribution_chart_uses_actual_alerts_and_handles_empty_input():
    from dashboard import _severity_distribution_chart

    assert _severity_distribution_chart([]) is None
    chart = _severity_distribution_chart(
        [
            {"base_severity": "High"},
            {"severity": "Critical"},
            {"base_severity": "High"},
            {"base_severity": "Unknown"},
        ]
    ).to_dict()

    assert chart["layer"][0]["data"]["values"] == [
        {"severity": "Critical", "count": 1},
        {"severity": "High", "count": 2},
    ]
    assert chart["layer"][1]["data"]["values"] == [{"total": 3}]
    assert chart["layer"][2]["mark"]["text"] == "ALERTS"
    assert chart["layer"][0]["encoding"]["color"]["legend"]["values"] == [
        "Critical",
        "High",
    ]
    assert chart["config"]["legend"]["labelColor"] == "#a7b7cc"


def test_parser_quality_chart_uses_only_reported_line_counters():
    from dashboard import _parse_quality_chart

    assert _parse_quality_chart({"lines_read": 0}) is None
    chart = _parse_quality_chart(
        {
            "lines_read": 10,
            "events_parsed": 6,
            "lines_ignored": 3,
            "lines_malformed": 1,
        }
    ).to_dict()

    assert [row["lines"] for row in chart["data"]["values"]] == [6, 3, 1]
    assert chart["encoding"]["x"]["title"] == "Input lines"
    assert chart["title"] == "Input-line disposition"


def test_overview_omits_local_processing_badge_and_uses_sparkle_brand():
    from streamlit.testing.v1 import AppTest

    script = """\
import streamlit as st
import dashboard
events, stats, result = dashboard.analyze_for_dashboard(
    dashboard.SAMPLE_LOGS["SSH sample"], log_type="ssh", year=2026
)
context = dashboard._dashboard_page_context(events, stats, result)
dashboard._render_soc_page(st, "Overview", context)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    assert not any("LOCAL PROCESSING" in item.value for item in app.markdown)
    assert not any("NO LOG UPLOAD" in item.value for item in app.markdown)
    assert _brand_asset_for_page("Overview").name == "sentinel-sparkle.svg"
    assert _brand_asset_for_page("Alerts").name == "sentinel-sparkle.svg"


def test_overview_brand_renderer_uses_compact_sparkle_and_accessible_page_title():
    from contextlib import nullcontext

    from dashboard import _render_brand_header

    class ColumnSpy:
        def __init__(self):
            self.image_call = None
            self.markdown_call = None
            self.caption_call = None

        def image(self, path, **kwargs):
            self.image_call = (path, kwargs)

        def markdown(self, value, **kwargs):
            self.markdown_call = value

        def caption(self, value):
            self.caption_call = value

        def title(self, value):
            self.page_title = value

    class StreamlitSpy(ColumnSpy):
        def container(self, **_kwargs):
            return nullcontext()

        def columns(self, *_args, **_kwargs):
            self.column = ColumnSpy()
            self.summary = ColumnSpy()
            return self.column, self.summary

    spy = StreamlitSpy()
    _render_brand_header(spy, "Overview")

    assert spy.column.image_call == (str(_brand_asset_for_page("Overview")), {"width": 40})
    assert spy.summary.page_title == "Security Operations Overview"
    assert spy.summary.caption_call == "Local security telemetry, detections, and risk at a glance."
    assert "LOCAL PROCESSING" not in (spy.summary.markdown_call or "")


def test_alert_page_uses_structured_details_and_keeps_raw_json_collapsed():
    from streamlit.testing.v1 import AppTest

    script = """\
import streamlit as st
import dashboard
events, stats, result = dashboard.analyze_for_dashboard(
    dashboard.SAMPLE_LOGS["SSH sample"], log_type="ssh", year=2026
)
context = dashboard._dashboard_page_context(events, stats, result)
dashboard._render_soc_page(st, "Alerts", context)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    raw_json = next(item for item in app.expander if item.label == "Raw JSON evidence")
    assert raw_json.proto.expanded is False
    assert any(item.label == "Attempts" for item in app.metric)
    assert any("Rule-level severity is distinct" in item.value for item in app.caption)


def test_incident_selection_id_is_stable_under_source_filter():
    start = datetime(2026, 10, 19, 8)
    events = [
        {
            "timestamp": start + timedelta(seconds=offset),
            "source_ip": "192.0.2.10",
            "event_type": "authentication_failure",
            "username": username,
        }
        for offset, username in enumerate(("a", "b", "c", "d", "e"))
    ]
    result = analyze_events(events)
    all_incident = result["incidents"][0]
    _, source_view = filter_dashboard_data(events, result, source_ip="192.0.2.10")

    assert source_view["incidents"][0]["incident_id"] == all_incident["incident_id"]


def test_dashboard_incident_attempts_do_not_count_noncontributing_successes():
    from detections import analyze_events

    start = datetime(2026, 10, 19, 9)
    source_ip = "192.0.2.77"
    events = []
    sequence = [
        (0, "authentication_failure"),
        (1, "authentication_success"),  # Below failure threshold; not alert evidence.
        (2, "authentication_failure"),
        (3, "authentication_failure"),
        (4, "authentication_failure"),
        (5, "authentication_failure"),
        (6, "authentication_success"),  # Qualifying success; part of alert evidence.
    ]
    for index, (seconds, event_type) in enumerate(sequence):
        events.append(
            {
                "_event_id": f"event-{index}",
                "timestamp": start + timedelta(seconds=seconds),
                "source_ip": source_ip,
                "username": "analyst",
                "event_type": event_type,
                "authentication_method": "password",
                "occurrence_count": 1,
            }
        )

    result = analyze_events(events)
    original_incident = result["incidents"][0]
    _, visible_result = filter_dashboard_data(events, result)

    assert original_incident["attempt_count"] == 6
    assert visible_result["incidents"][0]["attempt_count"] == original_incident["attempt_count"]


def test_dashboard_filters_drop_missing_timestamp_rows_safely():
    events = [
        {"source_ip": "192.0.2.10", "event_type": "authentication_failure"},
        {
            "timestamp": datetime(2026, 10, 19),
            "source_ip": "192.0.2.10",
            "event_type": "authentication_failure",
        },
    ]
    visible, _ = filter_dashboard_data(events, {"alerts": [], "risk_scores": {}, "incidents": []})
    assert len(visible) == 1


def test_filtered_download_sources_match_dashboard_scope():
    first = datetime(2026, 10, 19, 8)
    events = [
        {
            "timestamp": first + timedelta(seconds=offset),
            "source_ip": source_ip,
            "event_type": "authentication_failure",
            "username": "analyst",
        }
        for source_ip, base in (("192.0.2.10", first), ("192.0.2.11", first + timedelta(days=1)))
        for offset in range(5)
    ]
    result = analyze_events(events)
    filtered_events, filtered_result = filter_dashboard_data(
        events,
        result,
        source_ip="192.0.2.10",
        start_date=date(2026, 10, 19),
        end_date=date(2026, 10, 19),
    )

    csv_text = render_csv(filtered_result["alerts"])
    html_text = render_html_report(filtered_events, filtered_result)

    assert len(filtered_result["alerts"]) == 1
    assert set(filtered_result["risk_scores"]) == {"192.0.2.10"}
    assert "192.0.2.11" not in csv_text
    assert "192.0.2.11" not in html_text


def test_dashboard_analysis_discloses_timestamp_interpretation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Oct 19 09:00:00 host sshd[1]: Failed password for analyst from 192.0.2.10 port 22 ssh2\n",
        encoding="utf-8",
    )

    _, _, result = analyze_for_dashboard(log, log_type="ssh", year=2016)

    assert result["timestamp_interpretation"]["year_for_yearless_timestamps"] == 2016
    assert "timezone-unspecified" in result["timestamp_interpretation"]["timezone_assumption"]


def test_dashboard_successful_logins_page_renders_evidence_and_empty_values():
    from streamlit.testing.v1 import AppTest

    script = """\
import streamlit as st
import dashboard
result = dashboard.analyze_events([])
result["successful_logins"] = [{
    "timestamp": "2016-12-10T09:32:20",
    "source_ip": "192.0.2.70",
    "username": "analyst",
    "hostname": "edge",
    "process_id": 412,
    "session_identifier": None,
    "duration_seconds": 766,
    "related_failures": 0,
    "related_alert_rules": [],
    "correlation_status": "unique host/PID/username lifecycle match",
    "data_quality_limitations": ["no session ID in source log"],
}]
context = dashboard._dashboard_page_context([], {"lines_read": 0}, result)
dashboard._render_soc_page(st, "Successful Logins", context)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    assert any("Successful authentication observed" in item.value for item in app.caption)
    assert any("Session IDs are absent" in item.value for item in app.caption)


def test_dashboard_filter_scopes_successful_logins_by_source_and_parsed_date():
    result = analyze_events([])
    result["successful_logins"] = [
        {"timestamp": datetime(2016, 12, 10, 9), "source_ip": "192.0.2.10", "username": "alice"},
        {"timestamp": datetime(2016, 12, 10, 10), "source_ip": "198.51.100.10", "username": "bob"},
    ]

    _, filtered = filter_dashboard_data(
        [],
        result,
        source_ip="192.0.2.10",
        start_date=date(2016, 12, 10),
        end_date=date(2016, 12, 10),
    )

    assert [row["username"] for row in filtered["successful_logins"]] == ["alice"]


def test_source_page_displays_risk_factors_and_uncalibrated_confidence():
    from streamlit.testing.v1 import AppTest

    script = """\
import streamlit as st
import dashboard
from datetime import datetime, timedelta
base = datetime(2026, 10, 19, 9)
events = [{
    "timestamp": base + timedelta(seconds=i),
    "event_type": "authentication_failure",
    "source_ip": "192.0.2.44",
    "username": "root" if i == 0 else "analyst",
    "occurrence_count": 1,
} for i in range(5)]
result = dashboard.analyze_events(events)
context = dashboard._dashboard_page_context(events, {"authentication_failures": 5}, result)
dashboard._render_soc_page(st, "Sources", context)
"""
    app = AppTest.from_string(script).run(timeout=30)

    assert not app.exception
    assert any("not a probability of compromise" in item.value for item in app.caption)
    assert any("NAT or proxy source" in item.value for item in app.caption)
    assert any("Source-risk score explanation" in item.value for item in app.subheader)
    assert any("Rule Breadth" in str(frame.value) for frame in app.dataframe)


def test_data_quality_labels_password_failures_separately_from_method_probes():
    sections = data_quality_sections(
        {
            "lines_read": 2,
            "events_parsed": 2,
            "effective_event_occurrences": 2,
            "authentication_failures": 2,
            "password_authentication_failures": 1,
            "authentication_method_probes": 1,
        },
        [],
        log_type="ssh",
    )
    auth_metrics = dict(
        next(values for name, values in sections if name == "Authentication attempts")
    )

    assert auth_metrics["Failed authentication attempts (all methods)"] == 2
    assert auth_metrics["Failed password attempts"] == 1
    assert auth_metrics["Authentication-method probes (Failed none)"] == 1
