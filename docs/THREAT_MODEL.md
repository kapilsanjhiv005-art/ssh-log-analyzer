# Threat model

## Assets and boundaries

- Input SSH and web logs may contain secrets, usernames, addresses, request
  paths, and other sensitive data.
- Parsing, detection, filtering, and report generation run locally in the Python
  process. Uploaded dashboard files are written to a temporary directory under
  the ignored reports directory and removed when that context closes.
- The dashboard is configured to bind to `127.0.0.1`; operators should retain
  that setting when running it.
- Generated reports are local files or explicit user downloads. The application
  does not send logs to a service.

## Relevant threats and controls

| Threat | Controls in the current implementation | Remaining limitation |
|---|---|---|
| Malicious log text rendered as active HTML | HTML report escapes log-derived values; dashboard uses Streamlit text/table APIs; Markdown export escapes HTML and table delimiters | Review any exported report before sharing it |
| Spreadsheet formulas in exported text | CSV cells beginning with formula characters are prefixed as text | Spreadsheet behavior can vary by application |
| Oversized or malformed numeric fields | Parsers validate IPs, timestamps, ports, PIDs, and bound repeated-message weights | Parser support is limited to documented formats |
| Double counting from repeated/overlapping evidence | Weighted events avoid expansion; shared merger/correlation deduplicates stable event identities | Repeat-count interpretation must be confirmed for each source format |
| Alert overstatement from shared egress IPs | Reports distinguish rule severity from source-level composite risk | NAT/shared IPs can combine unrelated activity |
| Accidental external exposure | Loopback binding and disabled Streamlit usage statistics are configured | A user can override runtime settings or expose a host by changing them |

## Out of scope

The tool does not authenticate against hosts, block IPs, execute commands, or
confirm compromise. It does not perform cloud enrichment or external reputation
lookups. Source risk is a triage aid, not proof of malicious intent.
