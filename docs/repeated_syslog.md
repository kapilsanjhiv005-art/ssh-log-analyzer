# Repeated OpenSSH syslog records

## Semantics verified

For the supported rsyslog-style form
`message repeated N times: [<message>]`, `N` counts the suppressed copies of
the message. The original message is separate when it appears as its own log
record, so an original record followed by this summary represents `N + 1`
occurrences. The parser assigns `occurrence_count=N` to the summary record and
`occurrence_count=1` to the original record; it does not expand the summary into
individual event objects.

This interpretation is supported by rsyslog's implementation: its repeated
message handler increments `nsupp` for each duplicate it suppresses, then
generates the summary using that count and the stored message. When `nsupp` is
one, it emits the original message unchanged; when larger, it emits the
`message repeated N times: [...]` form. See the upstream
[rsyslog repeat-message handler](https://github.com/rsyslog/rsyslog/blob/main/runtime/ratelimit.c#L2184-L2233)
and [repeated-message reduction documentation](https://docs.rsyslog.com/doc/configuration/action/rsconf1_repeatedmsgreduction.html).

## Project verification

`sample_logs/repeated_syslog_semantics.log` is a **synthetic representative
fixture**, not a real operational log. It contains one failed root-authentication
record and a following rsyslog-style summary with `N=4`. The verified totals
are:

| Measure | Expected |
|---|---:|
| Input lines | 2 |
| Parsed event records | 2 |
| Effective event occurrences | 5 |
| Failed authentication occurrences | 5 |
| Root-login failure occurrences | 5 |
| Brute-force alert attempts | 5 |
| Root-attempt alert attempts | 5 |
| Correlated incident attempts | 5 |

The regression test checks these values in parser output, analyzer summary,
alert and incident structures, JSON, CSV, HTML, Markdown, and dashboard
analysis/chart inputs. The dashboard's severity cards count alerts, while its
failed-attempt timeline weights event occurrences; neither metric should be
read as the other.

## Limitations

No optional Loghub OpenSSH sample is present in this checkout, so this is not
verification against a real OpenSSH/syslog capture. The rule above applies to
the supported rsyslog-style format; other syslog daemons or custom templates
may use different repeat-count conventions or syntax. Confirm the source
daemon and format before interpreting a different summary line as this form.
