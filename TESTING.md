# Testing

Run `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m build`, and `python -m pip_audit .`. Tests cover privileged triggers, permissions, runner trust, immutable references, untrusted shell interpolation, discovery, hashing, CLI output, and invalid YAML roots.

## 1.1.0 regression acceptance

Run the complete existing suite plus the new regression fixtures. Confirm the documented command produces the selected output, malformed input remains actionable, and source files remain unchanged. Add SARIF source annotations and stable fingerprints, dated review exceptions, baseline comparisons and reusable/composite workflow coverage.

## Version 1.2.0: broader workflow review and portable baselines

Run the complete TESTING.md gates. Adversarial regressions cover trigger forms, privileged checkout refs, workflow-run artifacts, immutable container digests, remote scripts, malformed document shapes, value-free findings, HTML escaping, portable baselines, new-only thresholds, exclusions, and source preservation. Existing SARIF/baseline/exception tests must remain passing.

## 1.3.0 acceptance

Bind reviewed exceptions to the configuration they approved and reopen changed findings under new-only review.

Verify Emit value-free configuration digests and require a matching binding before suppressing a finding; Mark legacy unbound, expired and changed-configuration exceptions without applying them; Keep baseline identity stable while reporting updated configuration and rechecking it under new-only; Return actionable report-write errors without overwriting files. Run the full existing quality and build gates; release only through protected PR checks and verified tag artifacts.
