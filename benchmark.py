"""Offline 100,000-line parser/detection benchmark and window comparison."""

from __future__ import annotations

import tempfile
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from detections import analyze_events
from ssh_parser import parse_log_file

LINE_COUNT = 100_000
SOURCE_IP = "192.0.2.44"
WINDOW = timedelta(seconds=300)


def _make_line(index: int) -> str:
    """Return one synthetic failed-authentication line using a documentation IP."""
    stamp = datetime(2026, 1, 1) + timedelta(seconds=index)
    return (
        f"{stamp:%b %d %H:%M:%S} benchmark sshd[{index + 1}]: "
        f"Failed password for analyst from {SOURCE_IP} port 44000 ssh2\n"
    )


def _baseline_window_prune(timestamps: list[datetime]) -> int:
    """Measure the earlier list-filter window-pruning method for comparison."""
    active: list[datetime] = []
    maximum = 0
    for current in timestamps:
        active = [stamp for stamp in active if current - stamp <= WINDOW]
        active.append(current)
        maximum = max(maximum, len(active))
    return maximum


def _deque_window_prune(timestamps: list[datetime]) -> int:
    """Measure O(n) deque-based window pruning on the same timestamp series."""
    active: deque[datetime] = deque()
    maximum = 0
    for current in timestamps:
        while active and current - active[0] > WINDOW:
            active.popleft()
        active.append(current)
        maximum = max(maximum, len(active))
    return maximum


def run_benchmark(line_count: int = LINE_COUNT) -> dict[str, float | int]:
    """Generate, parse, and analyze synthetic records, then compare window scans."""
    report_dir = Path(__file__).resolve().parent / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sshlog-benchmark-", dir=report_dir) as directory:
        log_path = Path(directory) / "synthetic-auth.log"
        with log_path.open("w", encoding="utf-8", newline="") as output:
            output.writelines(_make_line(index) for index in range(line_count))

        started = time.perf_counter()
        events, stats = parse_log_file(log_path, year=2026)
        parsed_at = time.perf_counter()
        result = analyze_events(events)
        analyzed_at = time.perf_counter()
        timestamps = [event["timestamp"] for event in events]

        before_started = time.perf_counter()
        baseline_max = _baseline_window_prune(timestamps)
        before_elapsed = time.perf_counter() - before_started
        after_started = time.perf_counter()
        deque_max = _deque_window_prune(timestamps)
        after_elapsed = time.perf_counter() - after_started

    print(f"Synthetic lines: {stats['lines_read']:,}")
    print(f"Parsed events: {stats['events_parsed']:,}")
    print(f"Alerts: {len(result['alerts']):,}")
    parse_elapsed = parsed_at - started
    detection_elapsed = analyzed_at - parsed_at
    print(f"Parse time: {parse_elapsed:.3f}s")
    print(f"Detection time: {detection_elapsed:.3f}s")
    print(f"Parse + detection time: {analyzed_at - started:.3f}s")
    print(
        f"Before (list-filter window pruning): {before_elapsed:.3f}s; max window={baseline_max:,}"
    )
    print(f"After (deque window pruning): {after_elapsed:.3f}s; max window={deque_max:,}")
    return {
        "lines": stats["lines_read"],
        "events": stats["events_parsed"],
        "alerts": len(result["alerts"]),
        "parse_seconds": parse_elapsed,
        "detection_seconds": detection_elapsed,
        "analysis_seconds": analyzed_at - started,
        "before_seconds": before_elapsed,
        "after_seconds": after_elapsed,
    }


if __name__ == "__main__":
    run_benchmark()
