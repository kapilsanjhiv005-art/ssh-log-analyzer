"""Regression checks for linear alert-cluster boundary tracking."""

from datetime import datetime, timedelta

from detections import merge_adjacent_alerts


class CountingAlert(dict):
    """Count reads of the field used to track a merge cluster's end time."""

    last_seen_reads = 0

    def __getitem__(self, key):
        if key == "last_seen":
            type(self).last_seen_reads += 1
        return super().__getitem__(key)


class CountingEvidence(dict):
    """Count identity lookups made while merging event-count evidence maps."""

    get_reads = 0

    def get(self, key, default=None):
        type(self).get_reads += 1
        return super().get(key, default)


def test_adjacent_alert_merge_reads_cluster_end_a_bounded_number_of_times():
    """Merging a growing adjacent cluster should not rescan all prior alerts."""
    base = datetime(2026, 1, 1)
    alerts = [
        CountingAlert(
            rule="ssh_brute_force",
            source_ip="192.0.2.50",
            first_seen=base + timedelta(seconds=index),
            last_seen=base + timedelta(seconds=index + 1),
            window_seconds=60,
            attempt_count=1,
            _merge_event_ids=[str(index)],
            _merge_attempt_ids=[str(index)],
            _incident_event_counts=CountingEvidence({str(index): 1}),
            _merge_attempt_counts=CountingEvidence({str(index): 1}),
            usernames_targeted=[],
        )
        for index in range(200)
    ]
    CountingAlert.last_seen_reads = 0
    CountingEvidence.get_reads = 0

    merged = merge_adjacent_alerts(alerts)

    assert len(merged) == 1
    assert merged[0]["merged_alert_count"] == len(alerts)
    assert CountingAlert.last_seen_reads <= 3 * len(alerts)
    assert CountingEvidence.get_reads <= 3 * len(alerts)
    assert len(merged[0]["_incident_event_counts"]) == len(alerts)
