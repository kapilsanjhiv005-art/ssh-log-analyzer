# Implemented detection inventory

This inventory describes rules currently invoked by `analyze_events`. Defaults
come from `config.py` and `config.yaml`; configured values override the defaults.
Severity below is per-rule alert base severity unless explicitly stated.

| Rule ID and purpose | Trigger and defaults | Required fields | Severity behavior | MITRE ATT&CK | Existing tests | Known limits |
|---|---|---|---|---|---|---|
| `ssh_brute_force` — repeated SSH failures from one source | At least 5 weighted failures in an inclusive trailing 60-second window; the alert retains the full same-source activity wave while adjacent failures are no more than 60 seconds apart. | `timestamp`, `source_ip`, `event_type`; optional `occurrence_count` | Medium; High at configured 50 merged attempts; description marks sustained at 200. | T1110.001, Password Guessing | `tests/test_detections.py::test_brute_force_*`; phase 2 boundary/repeated tests | A continuous wave can span longer than 60 seconds when each inter-failure gap remains within the window; the qualifying peak remains bounded to a trailing 60 seconds. Shared NAT can combine users. |
| `ssh_low_and_slow_bruteforce` — sustained failures that evade the short window | Opt-in (`enabled: false`); default 20 weighted failures in an anchored 86,400-second window, only when no trailing configured brute-force window reaches its 5-attempt threshold. | `timestamp`, `source_ip`, `event_type`; optional `occurrence_count` | Medium | T1110.001, Password Guessing | `tests/test_low_and_slow.py`; `tests/test_evaluation_quality.py` | Has not been assessed on real benign traffic; anchored 24-hour windows can split events at boundaries; repeated counts remain subject to the short-window guard. |
| `ssh_password_spraying` — multi-account guessing observed from one source | At least 5 distinct usernames among failures in an anchored 60-second window. | Above plus `username` | Medium | —; no technique assigned because a shared password is not observed | `tests/test_detections.py::test_password_spraying_*`; `tests/test_phase2.py::test_password_spraying_and_single_account_brute_force_have_distinct_evidence` | Username spelling/normalization and shared egress affect distinct-account counts; can overlap brute force by design. |
| `ssh_username_enumeration` — invalid-user probing against distinct account names | At least 4 distinct invalid usernames in an anchored 60-second window. | Above plus `username`, `invalid_user` | Medium | —; no technique assigned because account discovery is not confirmed | `tests/test_detections.py::test_username_enumeration_*` | Depends on parser marking invalid-user records and log formats exposing that distinction. |
| `ssh_root_login_attempt` — failed root authentication | At least 3 weighted root failures in an anchored 60-second window; adjacent alerts merge by the configured gap. | `timestamp`, `source_ip`, `event_type`, `username` | Low; High at configured 50 merged attempts. | T1110, Brute Force | `tests/test_detections.py::test_root_*`; `tests/test_phase2.py::test_root_minimum_attempts_below_at_and_above_threshold` | Can overlap brute force on the same evidence; root aliases or policy-specific naming are not inferred. |
| `ssh_success_after_failures` — success after repeated SSH failures from the same source | At least 5 failures in the preceding 300 seconds before a successful authentication; successes are grouped within the lookback. A supported session-open record is attached as context only when host, `sshd` PID, and username match and it follows the success within that lookback. | `timestamp`, `source_ip`, `event_type`; optional matching session context | High | T1078, Valid Accounts | `tests/test_detections.py::test_success_after_*`; `tests/test_phase2.py::test_repeated_failures_qualify_success_after_failures`; `tests/test_ssh_session_context.py` | Indicates a sequence to investigate, not proof of compromise; auth correlation uses source IP, while session context requires matching host/PID/username; no `sudo`/`su` inference. |
| `ssh_distributed_bruteforce` — many sources fail against one account | At least 5 distinct source IPs against the same username in an anchored 120-second window. | `timestamp`, `source_ip`, `event_type`, `username` | High; source is represented by `source_ips`, not one `source_ip`. | T1110, Brute Force | `tests/test_phase2.py::test_distributed_bruteforce_positive_below_window_and_allowlist` | Source attribution and suppression are less granular for distributed patterns; NAT/proxies may distort apparent source count. |
| `ssh_off_hours_login` — successful SSH login outside configured business hours | Successful login outside 08:00–19:00 local log time; recent failures in the 300-second lookback raise base severity. | `timestamp`, `source_ip`, `event_type` | Low without recent failure; Medium when any recent failure exists. | T1078, Valid Accounts | `tests/test_phase2.py::test_off_hours_login_positive_business_hours_and_recent_failure_severity` | No timezone or holiday/calendar configuration; legitimate maintenance schedules can produce alerts. |
| `ssh_new_source_ip_login` — successful login from an address outside an explicit known-good allowlist | Runs only when an allowlist argument is supplied; success source is compared against it and configured trusted local sources. | `timestamp`, `source_ip`, `event_type`; explicit allowlist | Low | T1078, Valid Accounts | `tests/test_phase2.py::test_new_source_login_requires_allowlist_and_aggregates_successes`; loopback tests | “New” is approximated as not in the supplied allowlist; there is no historical baseline. |
| `web_login_bruteforce` — repeated unauthorized responses on configured login paths | At least 5 HTTP 401/403 responses to `/login`, `/wp-login.php`, or `/admin` in an anchored 60-second window. | `timestamp`, `source_ip`, `status`, `path` | Medium; High at configured 50 merged responses. | Unmapped; response status/path do not prove authentication attempts | `tests/test_web_logs.py::test_web_login_bruteforce_positive_below_window_and_allowlist` | Status codes and paths do not prove authentication attempts; custom login routes require configuration. |
| `web_scanning` — repeated not-found responses from one source | At least 10 HTTP 404 responses in an anchored 60-second window. | `timestamp`, `source_ip`, `status` | Medium; High at configured 50 merged responses. | T1595, Active Scanning | `tests/test_web_logs.py::test_web_scanning_positive_below_window_and_allowlist` | Broken links, crawlers, and application routing errors may look similar; no path entropy model. |
| `web_suspicious_user_agent` — configured scanner/tool text in User-Agent | Any request whose User-Agent contains a configured case-insensitive pattern (default: sqlmap, nikto, nmap, masscan, acunetix); grouped for 60 seconds. | `timestamp`, `source_ip`, `user_agent` | Low | T1595, Active Scanning | `tests/test_web_logs.py::test_suspicious_user_agent_positive_below_window_and_allowlist` | User-Agent is client-controlled and can be omitted or spoofed; substring matching can produce false positives. |
| `web_success_after_failures` — 2xx login-path response after repeated unauthorized responses | At least 5 401/403 responses, then a 2xx response to a configured login path within 60 seconds. | `timestamp`, `source_ip`, `status`, `path` | High | Unmapped; a 2xx response does not confirm authentication or a valid account | `tests/test_web_logs.py::test_web_success_after_failures_is_critical_and_allowlist_suppresses` | Same-IP linkage can conflate users behind NAT; 2xx is only a response signal and does not prove authentication succeeded. |

## Shared correlation and scoring

Adjacent same-rule/source alerts merge within their configured gap and retain
deduplicated event evidence. Incidents are created only when at least two
distinct rule IDs overlap in time for the same source IP. Incident evidence
counts the weighted union of contributing records rather than summing alert
attempt counts. Distributed alerts without one source IP do not form a normal
per-IP incident. Rule `base_severity`, per-source score/band, and composite
incident severity are separate values; source risk is a triage summary and can
be inflated by shared NAT egress. Success-after-failures is reported as a
possible compromise signal, not a confirmed conclusion.

The synthetic quality evaluation is documented in
[`evaluation.md`](evaluation.md). Its labels and metrics apply only to the
listed closed-set fixtures, not real-world detection performance.

## Post-login evidence boundary

The SSH parser retains supported `sshd` PAM session-open and session-close
records. A session-open record is attached to a success-after-failures alert
only when hostname, `sshd` PID, username, and the existing forward lookback
match. The session record contains no source address, so it is context rather
than an authentication event; session lifecycle records do not increase
authentication or incident attempt totals. Incident and report outputs
preserve linked session-open evidence. Session-close records are parsed and
accounted as context but are not currently linked to alerts.

The parser does not retain `sudo` or `su` records. Their actor, target user,
TTY, command, and process identity are log-format dependent; the SSH auth and
PAM session records do not provide a common TTY/session identifier. Linking
them by username and nearby time could attach an unrelated administrative
action to a login. A future implementation needs a product decision between
(1) showing parsed privilege events only as unlinked host-level context or
(2) requiring an explicit shared TTY/session key from compatible log sources
before linking them to an SSH session. No source-IP attribution or privilege
escalation conclusion should be inferred without such evidence.

There is no calibrated probabilistic confidence score. The existing rules,
their supporting evidence, and the distinct rule severity/source-risk fields
are the available confidence context; a numeric probability would require
representative labeled data and calibration. The current false-positive
control is the existing explicit IP/CIDR allowlist. Expiring suppressions
would need a defined rule/source scope, expiry policy, persistence and audit
record format, and operator workflow; they are not implemented because these
semantics have not been approved.
