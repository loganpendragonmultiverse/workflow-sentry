# Development handoff

Workflow Sentry is a read-only, local static analyzer for GitHub Actions. Version 1 deliberately avoids remote action resolution, automatic rewrites, secret access, and claims of complete workflow safety. Rule codes and value-free output are public contracts; additions require adversarial fixtures and must not echo secrets or expression values.

## 1.1.0 improvement session

Add SARIF source annotations and stable fingerprints, dated review exceptions, baseline comparisons and reusable/composite workflow coverage.

--format sarif emits SARIF 2.1.0 locations with one-based YAML node line/column regions and logical locations. Missing properties point to their parent node and are labeled regionExact=false. Fingerprints combine relative source path, rule and logical location, remaining stable when unrelated lines move; changing indexed steps can change fingerprints. --baseline accepts a prior JSON report. --exceptions accepts a JSON array of fingerprint, explanation and expires (ISO date); --as-of controls expiry comparison, defaulting to the current UTC date. Expired exceptions never suppress failure thresholds. Reports retain suppressed findings and distinguish new, unchanged and resolved fingerprints. Composite steps and unpinned reusable workflow calls are covered by fixtures. No workflow is run, changed, or automatically trusted.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.

## Version 1.2.0: broader workflow review and portable baselines

Add five rules for privileged event chains, attacker-controlled checkout refs, unpinned container action digests, downloaded scripts piped into interpreters, and workflow-run artifact review. Add escaped standalone HTML reports with remediation guidance, a rule inventory, source-root-relative baselines, repeated exclusions, and opt-in failure thresholds for newly introduced findings.
