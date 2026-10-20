# Synthetic performance check

Run the offline 100,000-line benchmark from the repository root:

```powershell
python benchmark.py
```

The benchmark generates OpenSSH-style failures with documentation-range IPs,
parses them, runs the full SSH analysis pipeline, and compares list-filter and
deque implementations of a trailing time-window scan. It does not read a real
log. Measurements are machine- and load-dependent; the following is one
before/after run on Python 3.13.15 on Windows, not a general performance claim.

| Measurement | Before alert-merge fix | After alert-merge fix |
|---|---:|---:|
| Lines/events | 100,000 / 100,000 | 100,000 / 100,000 |
| Parse time | 4.471 s | 5.608 s |
| Detection time | 91.912 s | 1.245 s |
| Parse + detection | 96.383 s | 6.852 s |

The fix avoids rescanning every alert's evidence-count map for each event
identity in an already merged cluster. It preserves the maximum count for
duplicate identities. A deterministic regression test checks the number of
identity lookups instead of asserting a timing threshold. Parse times varied
between the two runs, so compare primarily the large detection-time change;
repeat measurements under comparable system load before drawing broader
conclusions.
