# Contributing

Contributions should remain defensive and offline. Do not add network scanning, attack execution, real target IPs, or real authentication logs. Keep dependencies pinned and preserve the shared parser/detection/alert pipeline.

## Add a detection rule

1. Add a detection function in `detections.py` for SSH or `web_detections.py` for access logs. Accept normalized events and use the existing grouping/window helpers where they fit.
2. Create alerts with the shared `_base_alert` helper and add the rule's ATT&CK ID, technique name, and recommended action to `RULE_INFO` in `detections.py`. Include the rule's `window_seconds` so the shared adjacent-alert merger uses its detection window when the global merge gap is null.
3. Wire the rule into `_detect_all` and validated configuration defaults if the rule has tunable values. Keep allowlist handling consistent with existing rules.
4. Add tests for a positive case, a below-threshold case, a case outside the configured window, and allowlist suppression where applicable. Use documentation-range IPs only.
5. Run `python -m pytest -v`, `ruff check .`, and `ruff format --check .`. Check report output and update `README.md` and `docs/OUTPUTS.md` if the schema or behavior changed.

For a bug report, describe the issue without attaching real logs, credentials, hostnames, or personal data. Synthetic, sanitized examples are preferred.
