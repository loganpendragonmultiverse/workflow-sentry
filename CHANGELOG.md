# Changelog

## 1.2.0 - 2026-09-30

- Add WS010–WS014 for privileged checkout/event/artifact chains, mutable container actions, and remote scripts piped into interpreters.
- Recognize list-style workflow triggers as well as string and mapping forms.
- Add standalone HTML reports with review state and suggested remediation, plus `--list-rules`.
- Add `--root`, repeatable `--exclude`, and baseline-backed `--new-only` failure control.
- Retain existing default failure thresholds, value-free findings, review exceptions, JSON/Markdown/SARIF formats, and read-only analysis.

## 1.1.0 - 2026-09-07

- Add SARIF source annotations and stable fingerprints, dated review exceptions, baseline comparisons and reusable/composite workflow coverage.
- Added regression coverage for the audited behavior and invalid inputs.

## 1.0.0 - 2026-08-10

- Added local GitHub Actions workflow discovery and static security auditing.
- Added stable rule codes for permissions, triggers, runners, actions, credentials, secrets, and script injection.
- Added value-free Markdown and JSON reports plus configurable CI failure thresholds.
