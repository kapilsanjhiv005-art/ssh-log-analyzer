# Final Validation Report

**Date:** 2026-10-19
**Repository:** `C:\dev\ssh-log-analyzer`
**Branch:** `feat/repeated-lines-and-dashboard-v2`
**HEAD:** `424f7f8`
**Environment:** Windows, Python 3.13.15, repository `.venv`

## Status

The dashboard/product-audit milestone is **partially complete**. Core local dashboard investigation views and timeline brushing are implemented and tested; the browser interaction was verified with synthetic sample data. Release readiness is not claimed: there is no representative real-log corpus, the keyboard accessibility pass and exhaustive page/filter checks are incomplete, and some policy work requires an explicit decision.

## Work completed

- Added Data Quality's effective-occurrence metric, distinct from physical lines and parsed records.
- Clarified which dashboard views are scoped by source/date filters versus alert filters.
- Hardened Detection Coverage Markdown rendering so document links do not become dead local-app or external navigation links.
- Fixed timeline brush handling for epoch-millisecond bounds, emitted UTC chart values/labels, and added an explicit clear-selection button.
- Added dashboard helper/AppTest regressions for the above behavior and timeline selection parsing/filtering.
- Pinned Altair directly at `5.5.0` to make the timeline selection dependency explicit.
- Updated dashboard theme tokens, dashboard usage documentation, output documentation, branding notes, and the product audit.
- Recorded current validation and remaining limitations in this report.

No detection thresholds, risk formula, allowlist behavior, rule IDs, or incident policy were changed in this dashboard pass.

## Dashboard and browser evidence

Observed pages in the local Streamlit browser: Overview, Alerts, Incidents, Sources, Timeline, Detection Coverage, Data Quality, and Reports. Detailed Analysis has AppTest coverage, but was not included in this live-browser pass. Selected-source investigation showed the source's score/band, weighted outcomes, alerts, incident, methods, users, and activity.

Using the bundled synthetic SSH sample, the timeline table showed 37 events, a pointer brush reduced it to 15, and **Clear time selection** restored 37. The chart axis displayed UTC. Desktop (1440px) and narrow (391px) layouts were visually inspected. Dashboard AppTests cover startup and focused page rendering. A keyboard-only accessibility audit and exhaustive browser combinations of filters, export downloads, and empty/malformed uploads remain incomplete.

Browser console review found transient health-check connection/404 errors during server restarts and direct deep-link navigation. A stable in-app navigation to Timeline added no new browser console errors. The available browser surface did not expose request-level network-failure inspection; therefore this is not a complete browser-network audit. The application remains configured for local loopback operation with usage statistics disabled and no log-upload/enrichment code introduced by this work.

## Validation results

Commands were run with the repository virtual environment:

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_dashboard.py` | **30 passed** |
| `python -m pytest -v` | **146 passed, 2 skipped** |
| `ruff check .` | Passed: all checks passed |
| `ruff format --check .` | Passed: 33 files already formatted |
| `python -m pip check` | Passed: no broken requirements |
| `git diff --check` | Passed; Git printed line-ending normalization warnings for modified files |

The two skipped tests require the optional Loghub sample, which is not present. Tests use synthetic/local fixtures; they do not establish real-world detection accuracy.

## Files updated in this dashboard/audit pass

- `dashboard.py` — timeline UTC/brush/clear behavior, filter-scope guidance, effective-occurrence data quality, safe documentation-link rendering.
- `tests/test_dashboard.py` — focused helper, selection, and rendering regressions.
- `.streamlit/config.toml` — light theme and sidebar tokens.
- `pyproject.toml`, `requirements.txt` — explicit pinned Altair dependency.
- `README.md`, `docs/OUTPUTS.md`, `docs/BRANDING.md` — align user-facing dashboard/output/design documentation.
- `docs/PRODUCT_AUDIT_AND_IMPLEMENTATION_PLAN.md` — authoritative status and evidence.
- `docs/FINAL_VALIDATION_REPORT.md` — this report.

The repository already contained extensive uncommitted tracked and untracked work before this pass, including engine, parser, CLI, tests, docs, samples, and assets. That work was preserved. No files were staged, committed, pushed, or released; the working tree remains uncommitted for review.

## Remaining limitations and approvals

- Real-log evaluation still requires a representative, authorized corpus with documented format/version and ground truth. Optional Loghub tests remain skipped.
- The low-and-slow detector stays disabled by default; synthetic cases are not sufficient to establish a safe production default.
- No calibrated confidence score or scoped, expiring false-positive suppression policy exists. Implementing suppression requires decisions on rule/source scope, expiration, persistence, audit record, and review workflow.
- sudo/su linkage is intentionally not inferred from username/time proximity. A defensible shared TTY/session identity policy requires a product decision and supported records.
- Keyboard accessibility, full page-by-page browser checks, and full browser network-failure capture remain to be completed with appropriate tooling.
- No dependency advisory database scan was performed because it would require external vulnerability data; `pip check` only checks installed dependency consistency.
- No current 100,000-line benchmark was run as part of this dashboard pass; no new performance claim is made.

## Next milestone

Complete the remaining browser/accessibility and integration checks, then obtain an authorized representative SSH/web corpus and explicit policy decisions before calibrating confidence or introducing expiring suppression behavior. Preserve all established detection semantics until those gates are met.

## Follow-up: SOC dashboard redesign and final verification (2026-10-19)

The local Streamlit app was run and inspected in the in-app browser at approximately 391px. The Overview displayed the existing `sentinel-icon.svg`, light semantic KPI cards, sample/input context, local-processing indicator, and both charts. The Alerts investigation page displayed the rule/severity/source table, alert selection, attempt count, separate source risk score/band, MITRE fields, and evidence details. The mobile sidebar collapse handle initially overlapped the Overview icon; a responsive top inset now separates them. Screenshots were captured and inspected in the browser tool; no screenshot file was written into the repository. Desktop and 1024/768 widths were not rechecked in this follow-up.

A live SSH-to-web switch exposed stale rule and username filter state that hid web alerts. The regression was added first; after the fix, AppTest and browser verification showed all 3 web-sample alerts (2 Medium, 1 Low). The two data-dependent filter selections reset when their available options change. This does not modify source/date/severity/text filter behavior or analysis semantics.

Final validation after all edits:

| Command | Result |
|---|---|
| `.venv\\Scripts\\python.exe -m pytest -q tests/test_dashboard.py` | **47 passed** |
| `.venv\\Scripts\\python.exe -m pytest -v` | **163 passed, 2 skipped** |
| `.venv\\Scripts\\ruff.exe check .` | Passed: all checks passed |
| `.venv\\Scripts\\ruff.exe format --check .` | Passed: 33 files already formatted |
| `.venv\\Scripts\\python.exe -m pip check` | Passed: no broken requirements |
| `git diff --check` | Passed; Git only printed existing LF-to-CRLF normalization warnings |

Both skips require the optional Loghub sample, which is absent. The browser console check after the stable reload showed no error or warning entries. Earlier startup had emitted nonfatal empty sidebar theme-color warnings; they did not recur after removing the unsupported sidebar theme settings. Browser tooling does not expose request-level network inspection, and the app was not checked at desktop/intermediate viewport widths in this follow-up. No new dependency was introduced. No tests were weakened. The working tree remains uncommitted.

## Later maintainer-provided verification (supersedes earlier snapshots)

The results below were supplied by the maintainer for the v0.4.0 publication audit; they were not rerun during that audit. They are separate evidence categories:

| Check | Maintainer-reported result | Scope / limitation |
|---|---|---|
| Full pytest suite | **222 passed, 3 skipped** | All three skips require the optional local Loghub OpenSSH sample. |
| Separate real-dataset test run | **21 passed in 1.33 seconds** | A separate run; not part of the full-suite count. Dataset/version and exact invocation should be recorded by the maintainer before publication. |
| Runtime dependency vulnerability audit | No known vulnerabilities found | Audit database/tool and scan date were not included in the supplied evidence; do not treat this as a permanent guarantee. |
| Build dependency audit | `setuptools==83.0.0`: no known vulnerabilities found | This is the version pinned in `pyproject.toml`; audit tool/date were not supplied. |
| Ruff lint / format | Passed; 36 files formatted | Maintainer-reported. |
| `pip check` | Passed; no broken requirements | This checks installed dependency consistency, not package vulnerabilities. |
| `git diff --check` | Passed | Git emitted LF-to-CRLF warnings. |
| Dashboard manual check | Performed by maintainer | Exhaustive browser, keyboard accessibility, and cross-browser checks remain outstanding. |

The separate real-dataset result is evidence for that run only, not broad accuracy. The dataset is not bundled, and users must independently satisfy the dataset's terms. Historical dated results elsewhere in this report describe earlier snapshots and should not be read as the latest results.