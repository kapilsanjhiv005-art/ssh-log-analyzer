"""Optional invariant checks for a user-provided Loghub OpenSSH sample."""

from pathlib import Path

import pytest

import analyzer
from config import load_config
from detections import (
    analyze_events,
    detect_brute_force,
    detect_password_spraying,
    detect_root_attempts,
    detect_username_enumeration,
    merge_adjacent_alerts,
)
from ssh_parser import parse_log_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOGHUB_SAMPLE = PROJECT_ROOT / "sample_logs" / "OpenSSH_2k.log"


@pytest.mark.skipif(
    not LOGHUB_SAMPLE.is_file(), reason="local Loghub OpenSSH sample is not present"
)
def test_user_provided_loghub_sample_has_sensible_invariants() -> None:
    """Check parser, merge, score, and CLI behavior without pinning dataset counts."""
    events, stats = parse_log_file(LOGHUB_SAMPLE, year=2016)
    assert stats["events_parsed"] > 0
    config = load_config(None)
    raw_alerts = (
        detect_brute_force(events)
        + detect_password_spraying(events)
        + detect_username_enumeration(events)
        + detect_root_attempts(
            events,
            minimum_attempts=config["root_attempts"]["minimum_attempts"],
        )
    )
    merged_alerts = merge_adjacent_alerts(raw_alerts)
    assert len(merged_alerts) < len(raw_alerts)

    result = analyze_events(events, config=config)
    assert all(0 <= value["score"] <= 100 for value in result["risk_scores"].values())
    exit_code = analyzer.main(
        [
            "--file",
            str(LOGHUB_SAMPLE),
            "--year",
            "2016",
            "--format",
            "console",
            "--quiet",
        ]
    )
    assert exit_code in {1, 2}
