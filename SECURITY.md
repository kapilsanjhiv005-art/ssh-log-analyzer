# Security Policy

## Project Status

Sentinel Log Analyser is currently in public beta. It is intended for defensive security log analysis and is not guaranteed to be suitable for production use.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4   | No        |

Security fixes are evaluated against the latest beta release.

## Scope

This application is intended for defensive analysis of local SSH and web-server logs. It does not execute scans or attacks. Logs are processed in-process; the dashboard is configured for loopback access and usage statistics are disabled.

## Handling Sensitive Data

Do not commit real logs, credentials, private keys, hostnames, or personally identifiable information. Review generated reports before sharing them: they can contain usernames, source addresses, paths, and User-Agent values from the input.

HTML output escapes log-derived values, but this does not make a report appropriate to publish. Do not upload sensitive logs to public issues or third-party services for triage.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting feature for this repository to report suspected security vulnerabilities.

Do not disclose vulnerability details publicly before the maintainer has had an opportunity to investigate.

Please include, where possible:

- The affected version
- A description of the vulnerability
- Steps to reproduce the issue
- The potential security impact
- Relevant logs or evidence with sensitive information removed

For non-sensitive bugs, use the issue tracker with a synthetic reproduction and documentation-range IP addresses.

## Response and Disclosure

Reports will be reviewed by the maintainer as time permits. Please allow time for investigation before publicly disclosing an unpatched vulnerability.

This project is maintained on a best-effort basis. A response or fix within a specific timeframe is not guaranteed.