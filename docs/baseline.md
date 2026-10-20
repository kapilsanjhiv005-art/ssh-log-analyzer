# Repository Baseline

Captured during Phase 0 inspection on 2026-10-19. This records observed state before the next implementation phase; it is not a release-readiness claim.

## Repository state

- Repository: `C:\dev\ssh-log-analyzer`
- Branch: `feat/repeated-lines-and-dashboard-v2`
- HEAD: `424f7f8` (`Weighted repeated-message parsing, dashboard v2, parser coverage`)
- Git index and working tree: clean at inspection time.
- Python: 3.13.15 (Windows, project `.venv`).
- Project metadata: `sshlog-analyzer` 0.4.0; Python >=3.11; CLI entry point `sshlog-analyzer = analyzer:main`.

## Baseline checks

| Command | Result |
|---|---|
| `python -m pytest -v` | 84 passed, 2 skipped (2.62 seconds) |
| `python -m ruff check .` | Passed; all checks passed |
| `python -m ruff format --check .` | Passed; 19 files already formatted |
| `python -m pip check` | Passed; no broken requirements |

The two skipped tests exercise the optional Loghub OpenSSH sample, which is not present in this checkout. These checks establish synthetic-fixture and bundled-test baseline behavior; they do not verify behavior on that real-log dataset.

`pip-audit` is installed. It was not run during this offline-only baseline because its vulnerability database lookup can contact an external service. `bandit` is not installed/configured in the project environment.

## Inspected project areas

The repository contains the CLI/analyzer, SSH and combined web-log parsers, SSH and web detection modules, shared alert/incident correlation and source-risk logic, YAML configuration and allowlists, CSV/JSON/HTML exporters, a local Streamlit dashboard, synthetic log generators, tests, documentation, and GitHub Actions CI. `pyproject.toml` pins runtime and development dependencies and declares Python 3.11+ support. CI is configured for Python 3.11, 3.12, and 3.13.

The `reports/` directory is Git-ignored and contains no tracked files. No root `AGENTS.md`, `SECURITY.md`, or `CHANGELOG.md` was present during inspection. The Streamlit project configuration binds to loopback and disables usage statistics.

## Baseline limitations

- The optional Loghub test data is absent, so real-log parser accounting and any reported real-log root-attempt reconciliation remain unverified.
- No edits to application code or tests were made as part of this baseline capture.
