# Synthetic detection evaluation

Run the deterministic, offline scenario suite from the repository root:

```powershell
python -m tools.evaluate_quality
```

Scenario inputs and expected alert counts are declared in
`tools/evaluate_quality.py` before evaluation. The suite covers all current
SSH and web rules, benign authentication and requests, below-threshold and
outside-window controls, multi-account guessing, invalid-user probing, root
failures, confirmed-success sequences, a weighted repeated-syslog fixture,
overlapping rules, separated adjacent windows, distributed attempts,
off-hours and new-source logins, opt-in low-and-slow failures, legitimate
low-volume administration, and a benign root-administration scenario. All generated IPs are from documentation
ranges. The only parsed fixture is the clearly labeled synthetic
`sample_logs/repeated_syslog_semantics.log`.

Metrics classify each scenario/rule pair using the declared `truth` labels;
`expected` separately pins the exact rule alert counts so a deterministic
change in output also fails the golden comparison. Precision, recall, and F1
are therefore scenario-level, not per-event statistics. A labeled legitimate
root-administration scenario intentionally produces a root-attempt alert and
is counted as one synthetic false positive. Rule overlap is not treated as a
duplicate: both rule identities remain present, while their incident evidence
is deduplicated.

The suite includes 32 synthetic scenarios. The last recorded run produced:

| Rule | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| `ssh_brute_force` | 5 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `ssh_low_and_slow_bruteforce` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `ssh_password_spraying` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `ssh_username_enumeration` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `ssh_root_login_attempt` | 2 | 1 | 0 | 0.6667 | 1.0000 | 0.8000 |
| `ssh_success_after_failures` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `ssh_distributed_bruteforce` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `ssh_off_hours_login` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `ssh_new_source_ip_login` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `web_login_bruteforce` | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `web_scanning` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `web_suspicious_user_agent` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| `web_success_after_failures` | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

These perfect scores for most rules only mean the implementation matches these
small declared cases; they are not field precision, recall, false-positive
rates, comparative results, or estimates of real-log performance. The root
rule's single false positive demonstrates the effect of benign privileged
administration that resembles repeated root failures. No real logs or user
data are included. Add reviewed, labeled synthetic cases as a rule changes;
keep real authorized logs outside version control. Real-world accuracy remains
unvalidated because the optional Loghub sample is unavailable and these cases
do not represent operational traffic diversity.

The earlier narrow parser-fixture comparison remains available as:

```powershell
python tools/evaluate_synthetic.py
```
