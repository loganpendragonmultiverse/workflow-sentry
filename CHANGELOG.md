# Changelog

## 1.4.1 - 2026-10-19

- Return exit status 2 for failed stdout writes, including closed pipes, without an extra interpreter shutdown warning.

## 1.4.0 - 2026-10-17

- Track scanned, excluded and unscanned baseline sources. Findings omitted from the current scan are unverified rather than resolved.
- Quoted strings inside GitHub expressions no longer trigger WS009, while equivalent dot and literal-index event references are checked. This remains a static check: dynamically computed index keys still require manual review.

## 1.3.2 - 2026-10-17

- Check explicit self-hosted labels in mapping-form runner selections as well as direct labels.
- Require GitHub expression delimiters before reporting untrusted event-text interpolation in shell scripts.

## 1.3.1 - 2026-10-17

- Correct the stale release version in the README scope section and align the current-release documentation with this patch.
- Preserve the 1.3.0 analysis behavior and public contracts.

## 1.3.0 - 2026-10-17

- Emit value-free configuration digests and require a matching binding before suppressing a finding
- Mark legacy unbound, expired and changed-configuration exceptions without applying them
- Keep baseline identity stable while reporting updated configuration and rechecking it under new-only
- Return actionable report-write errors without overwriting files

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
