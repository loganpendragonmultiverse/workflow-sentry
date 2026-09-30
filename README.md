# Workflow Sentry

Workflow Sentry audits GitHub Actions YAML locally for high-impact security risks before a workflow is merged.

It checks explicit token permissions, immutable action references, `pull_request_target`, self-hosted runners, inherited reusable-workflow secrets, checkout credential persistence, and direct shell interpolation of untrusted event text. Required `security-events: write` access is surfaced as informational evidence rather than treated as a defect. Reports contain rule locations and classifications, not repository secrets or workflow values.

## What it checks

- Add WS010–WS014 for privileged checkout/event/artifact chains, mutable container actions, and remote scripts piped into interpreters.
- Recognize list-style workflow triggers as well as string and mapping forms.
- Add standalone HTML reports with review state and suggested remediation, plus `--list-rules`.
- Add `--root`, repeatable `--exclude`, and baseline-backed `--new-only` failure control.
- Retain existing default failure thresholds, value-free findings, review exceptions, JSON/Markdown/SARIF formats, and read-only analysis.

## Three-minute start

```bash
python -m pip install .
workflow-sentry .github/workflows --format markdown --output workflow-security.md
workflow-sentry .github/workflows --format json --fail-on high
```

Exit status is `1` when a finding meets `--fail-on`. The default threshold is `critical`.

## Scope and limitations

- Static analysis cannot prove a workflow safe or determine whether referenced third-party code is trustworthy.
- Full commit-SHA pinning is treated as immutable; local and `docker://` actions are handled separately.
- Expression checks are deliberately narrow and evidence-based, so novel injection patterns may require manual review.
- No network request, GitHub token, repository mutation, telemetry, or workflow execution occurs.

Supported on Python 3.10+ for Windows, macOS, and Linux. Version: **v1.2.0**.

## Development

```bash
python -m pip install -e ".[dev]"
ruff format --check . && ruff check .
mypy src
pytest
python -m build
```

Security reports belong in `SECURITY.md` through the organization policy. Contributions are reviewed through pull requests. Licensed under MIT.

## Version 1.1.0: reviewed improvements

Add SARIF source annotations and stable fingerprints, dated review exceptions, baseline comparisons and reusable/composite workflow coverage.

```bash
workflow-sentry .github/workflows --format sarif --output workflow-review.sarif
```

--format sarif emits SARIF 2.1.0 locations with one-based YAML node line/column regions and logical locations. Missing properties point to their parent node and are labeled regionExact=false. Fingerprints combine relative source path, rule and logical location, remaining stable when unrelated lines move; changing indexed steps can change fingerprints. --baseline accepts a prior JSON report. --exceptions accepts a JSON array of fingerprint, explanation and expires (ISO date); --as-of controls expiry comparison, defaulting to the current UTC date. Expired exceptions never suppress failure thresholds. Reports retain suppressed findings and distinguish new, unchanged and resolved fingerprints. Composite steps and unpinned reusable workflow calls are covered by fixtures. No workflow is run, changed, or automatically trusted.

## Version 1.2.0: reviewed improvements

Add five rules for privileged event chains, attacker-controlled checkout refs, unpinned container action digests, downloaded scripts piped into interpreters, and workflow-run artifact review. Add escaped standalone HTML reports with remediation guidance, a rule inventory, source-root-relative baselines, repeated exclusions, and opt-in failure thresholds for newly introduced findings.

```bash
workflow-sentry --list-rules
workflow-sentry .github/workflows --root . --format html --output new-review.html
workflow-sentry .github/workflows --root . --format json --output baseline.json
workflow-sentry .github/workflows --root . --baseline baseline.json --new-only --fail-on high
workflow-sentry .github/workflows --root . --exclude '.github/workflows/fixtures/*'
```

Use the same `--root` for both baseline creation and comparison. `--new-only` requires a baseline and changes failure evaluation only; all findings remain in the report. Excluding every source is an input error. WS011/WS014 flag trust-boundary reviews and do not prove exploitation. WS012 accepts full SHA-256 container digests; WS013 recognizes a narrow remote-download pipe pattern. Static analysis still requires human review.
