# Output formats and schemas

## JSON

`alerts.json` is a UTF-8 JSON object with these top-level fields:

| Field | Type | Meaning |
|---|---|---|
| `alerts` | array of objects | Alerts retained after optional minimum-severity filtering |
| `incidents` | array of objects | Correlated overlapping alerts, with `incident_id`, `source_ip`, first/last timestamps, contributing rules, combined severity, summary, deduplicated attempt/user/method evidence, and the event identities belonging to the incident |
| `risk_scores` | object keyed by source IP | Each value has integer `score` and string `band` |
| `alerts_suppressed` | integer | Alert count suppressed by the allowlist |
| `config_used` | object | Validated effective configuration after CLI overrides |
| `parse_stats` | object | Physical-line counters plus weighted record and terminal-attempt counts. SSH failure/success counters include only terminal `Failed`/`Accepted` outcomes; Invalid-user, PAM, and `input_userauth_request` records remain context. Context link/unattributed counters are also included. See [counting semantics](counting-semantics.md). Repeated-message weights never expand physical-line counters. |
| `version` | string | Analyzer version |
| `schema_version` | integer | Report schema version (currently 7; terminal-outcome attempt accounting, incident evidence identities, timestamp interpretation, and successful-login inventory) |
| `timestamp_interpretation` | object | Selected year and timezone assumptions for timestamps in this analysis |
| `successful_logins` | array of objects | Successful SSH authentication records with cautious lifecycle correlation and limitations |
| `risk_explanations` | object keyed by source IP | Existing risk-score factor evidence and contributions; confidence remains explicitly uncalibrated |
| `generated_at` | ISO-8601 string | ISO-8601 report-generation timestamp in UTC |

Each alert includes the common fields `rule`, `severity`, `base_severity`, `source_ip`, `first_seen`, `last_seen`, `attempt_count`, `usernames_targeted`, `authentication_methods`, `description`, `mitre_attack_id`, `mitre_technique_name`, and `recommended_action`. An optional `mitre_mapping_note` explains when an observed pattern is intentionally left unmapped. `severity` and `base_severity` identify the rule-level severity. Source-based alerts also include `source_risk_score` and `source_risk_band`, which describe composite per-IP risk; legacy `risk_score` and `risk_band` fields remain as aliases. Incidents include `combined_severity`, `risk_score`, and `risk_band`; combined severity is derived from the documented source risk band. Rule-specific details may add fields such as `paths`, `statuses`, `user_agent`, `source_ips`, or `target_username`. Terminal authentication events may carry `supporting_evidence` from context lines linked by host, PID, username, compatible IP, and unique timestamp proximity; these records do not increase attempt counts. This evidence is retained on relevant alerts and incidents in JSON, CSV, HTML, and Markdown. A success-after-failures alert can include `session_activity` context when a session-open record matches the successful authentication's host, `sshd` PID, and username within the existing lookback; it does not change attempt counts. Correlated incidents preserve this deduplicated context as evidence only, also without changing attempt counts. When adjacent alerts are merged, `merged_alert_count` and `unique_event_count` report aggregation size. Timestamp values are serialized as ISO-8601 strings. Fields can vary by rule.

Timestamp-bearing JSON reports include `timestamp_interpretation`. SSH yearless syslog records use the selected `--year` and retain timezone-unspecified wall-clock values; ISO timestamps with explicit offsets normalize to UTC. Nginx/Apache combined timestamps include explicit offsets and normalize to UTC. HTML, Markdown, CSV, and dashboard views carry the same interpretation; table labels use neutral parsed-timestamp wording where the source zone is unknown. CSV remains alert-row based and repeats the interpretation metadata on each row.

## CSV

`alerts.csv` contains one row per alert. `successful_logins.csv` is a separate event-row inventory so authentication events do not change alert-row CSV semantics. The core columns are:

```text
rule,severity,source_ip,first_seen,last_seen,attempt_count,usernames_targeted,
base_severity,description,mitre_attack_id,mitre_technique_name,recommended_action,source_risk_score,source_risk_band,risk_score,risk_band
```

Non-empty exports add the union of rule-specific alert keys present in that run. An empty export contains the core header columns. List and mapping values are serialized to JSON-compatible strings; timestamps use ISO-8601. Analysis-generated CSV includes the same `timestamp_interpretation` metadata column on every row; an empty export carries it in its header only.

## HTML

`report.html` is a standalone report containing severity counts, parser coverage, suppressed-alert count, incidents, risky IPs, alert details and timeline, effective configuration, and two PNG charts embedded as base64 data URIs. It has inline CSS and does not fetch network resources. Log-derived text is escaped before being inserted into the document.

The optional CLI `--show-malformed` adds at most 100 line-number/reason entries to `parse_stats` and prints at most 50 of them in the console. It never includes the original log line text. The dashboard collects the same bounded locations for its malformed-record expander. `malformed_by_reason` counts all malformed lines even when sample locations are not requested.

Physical-line counters partition as `lines_read = events_parsed + lines_ignored + lines_malformed`. `effective_event_occurrences` includes weighted parsed context records; `effective_authentication_attempts` counts only weighted terminal outcomes. CSV remains alert-row based and therefore does not contain parser totals.

## Markdown

The dashboard can download a Markdown analysis report containing severity counts, parser coverage, successful logins, incidents, and alert details. It uses the same filtered analysis result as the JSON, CSV, and HTML downloads. Log-derived values are HTML-escaped and normalized for Markdown table cells. Markdown is currently a dashboard export; it is not a CLI `--format` option.

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
