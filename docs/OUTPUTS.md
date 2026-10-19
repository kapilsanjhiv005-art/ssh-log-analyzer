# Output formats and schemas

## JSON

`alerts.json` is a UTF-8 JSON object with these top-level fields:

| Field | Type | Meaning |
|---|---|---|
| `alerts` | array of objects | Alerts retained after optional minimum-severity filtering |
| `incidents` | array of objects | Correlated overlapping alerts, with `incident_id`, `source_ip`, first/last timestamps, contributing rules, combined severity, summary, and available deduplicated attempt/user/method evidence |
| `risk_scores` | object keyed by source IP | Each value has integer `score` and string `band` |
| `alerts_suppressed` | integer | Alert count suppressed by the allowlist |
| `config_used` | object | Validated effective configuration after CLI overrides |
| `parse_stats` | object | input-line counters: `lines_read`, `events_parsed` (parsed source records), `lines_ignored`, and `lines_malformed`; repeated-message occurrence weights are not expanded into line counters |
| `version` | string | Analyzer version |
| `schema_version` | integer | Report schema version (currently 3) |
| `generated_at` | ISO-8601 string | ISO-8601 report-generation timestamp (UTC in CLI reports) |

Each alert includes the common fields `rule`, `severity`, `base_severity`, `source_ip`, `first_seen`, `last_seen`, `attempt_count`, `usernames_targeted`, `authentication_methods`, `description`, `mitre_attack_id`, `mitre_technique_name`, and `recommended_action`. `severity` and `base_severity` identify the rule-level severity. Source-based alerts also include `source_risk_score` and `source_risk_band`, which describe composite per-IP risk; legacy `risk_score` and `risk_band` fields remain as aliases. Incidents include `combined_severity`, `risk_score`, and `risk_band`; combined severity is derived from the documented source risk band. Rule-specific details may add fields such as `paths`, `statuses`, `user_agent`, `source_ips`, or `target_username`. When adjacent alerts are merged, `merged_alert_count` and `unique_event_count` report aggregation size. Timestamp values are serialized as ISO-8601 strings. Fields can vary by rule.

## CSV

`alerts.csv` contains one row per alert. The core columns are:

```text
rule,severity,source_ip,first_seen,last_seen,attempt_count,usernames_targeted,
base_severity,description,mitre_attack_id,mitre_technique_name,recommended_action,source_risk_score,source_risk_band,risk_score,risk_band
```

Non-empty exports add the union of rule-specific alert keys present in that run. An empty export contains the core header columns. List and mapping values are serialized to JSON-compatible strings; timestamps use ISO-8601.

## HTML

`report.html` is a standalone report containing severity counts, parser coverage, suppressed-alert count, incidents, risky IPs, alert details and timeline, effective configuration, and two PNG charts embedded as base64 data URIs. It has inline CSS and does not fetch network resources. Log-derived text is escaped before being inserted into the document.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | No alerts |
| 1 | Alerts found, no High alert or incident |
| 2 | High alert or incident present |
| 3 | File, configuration, permission, or other expected input/analysis error |

When `--min-severity` is set, exit status is based on the filtered alerts and incidents. A live follow session returns 0 on clean stop.

## Risk scores and bands

The score is `min(10 × distinct rules, 40) + min(20, int(20 × log1p(failures) / log1p(1000))) + 15 for root targeting + 30 for confirmed success-after-failures`, clamped to 0–100. Confirmed SSH or web success-after-failures guarantees at least 75 (Critical); all other activity is capped at 74. Bands: 0–24 Low, 25–49 Medium, 50–74 High, and 75–100 Critical. Correlated incident `combined_severity` is the source risk band; individual alert `base_severity` remains rule-level. Ties sort by total source events, then most recent event, then IP.
