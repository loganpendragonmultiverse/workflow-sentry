# Testing

Run `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m build`, and `python -m pip_audit .`. Tests cover privileged triggers, permissions, runner trust, immutable references, untrusted shell interpolation, discovery, hashing, CLI output, and invalid YAML roots.

## 1.1.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Add SARIF source annotations and stable fingerprints, dated review exceptions, baseline comparisons and reusable/composite workflow coverage.

## Version 1.2.0: broader workflow review and portable baselines

Run the complete TESTING.md gates. Adversarial regressions cover trigger forms, privileged checkout refs, workflow-run artifacts, immutable container digests, remote scripts, malformed document shapes, value-free findings, HTML escaping, portable baselines, new-only thresholds, exclusions, and source preservation. Existing SARIF/baseline/exception tests must remain passing.

## 1.3.0 acceptance

Bind reviewed exceptions to the configuration they approved and reopen changed findings under new-only review.

Verify Emit value-free configuration digests and require a matching binding before suppressing a finding; Mark legacy unbound, expired and changed-configuration exceptions without applying them; Keep baseline identity stable while reporting updated configuration and rechecking it under new-only; Return actionable report-write errors without overwriting files. Run the full existing quality and build gates; release only through protected PR checks and verified tag artifacts.

## 1.3.2 runner and interpolation regression acceptance

Verify mapping-form runner labels produce WS005, plain event-path text does not produce WS009, and actual inline GitHub expressions still do. Exercise CLI JSON, SARIF and exit thresholds using disposable workflow files. Run the existing quality gates and installed tag-built wheel regressions.

## 1.4.0 regression acceptance

Quoted strings inside GitHub expressions no longer trigger WS009, while equivalent dot and literal-index event references are checked. This remains a static check: dynamically computed index keys still require manual review.

Run the new source and CLI regression cases with the complete existing quality gates. Recheck installed tag-built artifacts after review and release approval.

## 1.4.0 report controls

Baseline comparisons now distinguish resolved findings from unverified findings in sources not scanned. Reports record scanned sources, excluded discovered sources and baseline sources omitted from this run. A missing or excluded file is not proof of resolution; use the same source root for comparable runs. Failure thresholds still apply only to findings actually scanned.

## 1.4.1 stdout regression acceptance

Exercise real closed stdout pipes with small and large reports, complete normal output, partial and zero descriptor writes, and in-memory streams. Verify status 2 without an ignored shutdown exception, unchanged source files, and existing report and output-file contracts.
