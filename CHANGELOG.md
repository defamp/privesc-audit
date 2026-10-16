# Changelog

## v0.5.0 — 2026-10-16

- Add Markdown baseline/diff reports with baseline metadata and finding counts.
- Include new, changed-severity and resolved findings, evidence, remediation and ATT&CK mappings.
- Escape Markdown table content and preserve multiline evidence.
- Support `--baseline baseline.json --format markdown -o diff.md`.
- Preserve regression exit codes: 0 = no regression, 1 = lower-severity regression, 2 = High/Critical regression.
- Add five tests; all 32 tests pass locally.

## v0.4.0

- Add baseline snapshots and regression diff mode.
- Include six check categories, including privilege-granting groups.
