# Parser and event counting semantics

These metrics describe different analysis layers; they are not expected to
have the same value.

| Metric | Definition |
|---|---|
| `lines_read` | Physical input lines yielded by the text reader, including blank/comment lines. A final unterminated line still counts once. |
| `events_parsed` | Retained records returned for analysis. For SSH, these are terminal authentication outcomes, recognized authentication context (`Invalid user`, PAM auth failure, and `input_userauth_request`), and supported connection/session context records. For web, these are successfully parsed combined access-log requests. |
| `lines_ignored` | Input lines intentionally outside the parser's retained event scope, including unrelated service lines and web blank/comment lines. Recognized SSH context is retained and is not ignored. |
| `lines_malformed` | Lines that appear to be in the selected parser's scope but fail required format or field validation. `malformed_by_reason` categorizes these physical lines. |
| `effective_event_occurrences` | Sum of each retained record's positive `occurrence_count`; ordinary records represent one. A repeat-summary record represents only its reported suppressed copies. Context record occurrences are included here, but not in authentication-attempt counts. |
| `effective_authentication_attempts` | Weighted count of terminal SSH outcomes: `Failed password`, `Failed publickey`, `Accepted password`, `Accepted publickey`, and other supported `Failed`/`Accepted` methods. |
| `authentication_failures` / `authentication_successes` | Weighted terminal outcomes across methods; `password_authentication_failures` is the password-only subset and `authentication_method_probes` counts `Failed none` separately. Failed-none probes remain in the broad failure total but are excluded from password-oriented detections. `Invalid user`, PAM auth-failure, and `input_userauth_request` lines are supporting context, not separate attempts. |
| `root_authentication_failures` / `root_authentication_successes` | Weighted root-user subsets of the corresponding SSH outcome counters. |
| `authentication_context_records` / `authentication_context_categories` | Physical retained context records, with separate counts for explicit invalid-user observations, PAM auth failures, and `input_userauth_request` messages. These categories remain supporting evidence and do not count as terminal outcomes. |
| `parsed_record_categories` | Physical retained records by event type, including connection closures, identification failures, suspicious reverse-mapping notices, and session-open/session-close messages. |
| `records_requiring_contextual_correlation` | Alias count for retained authentication-context records that may support an outcome but never count as an outcome on their own. |
| `supporting_evidence_records` | Context records linked to exactly one terminal outcome using matching host, sshd PID, username, compatible source IP, and a maximum timestamp gap of 10 seconds. A context record with multiple possible outcomes is left unlinked. |
| `unattributed_contextual_records` | Retained contextual records that remain without a directly parsed or defensibly correlated source IP. Hostnames in `rhost` are not treated as IP addresses. |
| `records_without_direct_source_ip` | Retained input records that did not have a source IP parsed directly. A linked context record can have a correlated IP while still being represented here as lacking direct attribution. |
| Brute-force activity wave | A same-source group continues while adjacent failures are no more than the configured window apart. It is emitted only if an inclusive trailing window reaches the threshold; once qualified, the alert retains all unique weighted records in the wave, even if the wave span exceeds one window. A gap greater than the window starts a separate wave. |
| Alert `attempt_count` | Rule-specific evidence count. It counts the weighted evidence relevant to that rule; for success-after-failures it counts the failures, not the successful login. |
| Incident `attempt_count` | Weighted event occurrences in the union of contributing rule evidence, deduplicated by event identity. It is not the sum of alert attempt counts, so a qualifying success event can contribute once. |

For either parser, physical-line accounting partitions as:

```text
lines_read = events_parsed + lines_ignored + lines_malformed
```

Repeated weights do not alter that equation: one repeat-summary line is still
one input line and one parsed event record. Its represented occurrences are
reported separately in `effective_event_occurrences` and applicable alert or
incident evidence totals. For the supported rsyslog-style format, `N`
suppressed duplicates plus a separate original record represent `N + 1`
occurrences; see [repeated syslog semantics](repeated_syslog.md). A support
record does not become a failure if a matching terminal outcome is absent.

The parser never fabricates a source IP from a PAM `rhost` hostname. It may
attach that context to one outcome only when the host, PID, username, and
timestamp match uniquely. Root and username summaries in source investigation
use events directly attributable to the selected source. Incident timelines
use the event identities recorded as that incident's evidence, rather than
all events that happen to share the incident's time span.

The CLI, dashboard, JSON, HTML, and Markdown outputs expose the appropriate
subset of these metrics. CSV is intentionally alert-row based: it carries each
rule's `attempt_count`, but not parser counters or incident rows. Dashboard
severity cards count alerts; parser coverage reports weighted input outcomes;
the failure timeline weights event occurrences. Filtered dashboard incidents
retain the evidence totals of their original correlated incidents instead of
recounting unrelated events that happen to fall between their timestamps.

## Evidence boundary

The automated accounting regression uses a synthetic fixture with
documentation-range addresses. The optional Loghub sample is absent, so these
checks do not establish real-log accounting accuracy for a particular host,
OpenSSH version, or syslog daemon.
