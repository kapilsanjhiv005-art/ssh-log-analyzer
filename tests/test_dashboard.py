"""Tests for the dashboard's shared analysis helper."""

from datetime import datetime

from dashboard import analyze_for_dashboard, risk_band_badge


def test_dashboard_risk_badge_uses_critical_color_and_escapes_label():
    badge = risk_band_badge("Critical")
    assert "#ffebee" in badge
    assert ">Critical</span>" in badge
    assert "&lt;script&gt;" in risk_band_badge("<script>")


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


def test_dashboard_analysis_respects_threshold_and_reports_shared_alert(tmp_path):
    log = tmp_path / "access.log"
    row = '192.0.2.7 - - [19/Oct/2026:08:00:00 +0000] "POST /login HTTP/1.1" 401 12 "-" "Browser"'
    log.write_text("\n".join([row] * 5) + "\n", encoding="utf-8")

    _, _, result = analyze_for_dashboard(log, log_type="web", year=2026, threshold=5)

    assert result["alerts"][0]["rule"] == "web_login_bruteforce"
    assert result["alerts"][0]["mitre_attack_id"] == "T1110"
