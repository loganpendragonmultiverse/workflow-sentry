# Development handoff

Workflow Sentry is a read-only, local static analyzer for GitHub Actions. Version 1 deliberately avoids remote action resolution, automatic rewrites, secret access, and claims of complete workflow safety. Rule codes and value-free output are public contracts; additions require adversarial fixtures and must not echo secrets or expression values.

## 1.1.0 improvement session

Add SARIF source annotations and stable fingerprints, dated review exceptions, baseline comparisons and reusable/composite workflow coverage.

--format sarif emits SARIF 2.1.0 locations with one-based YAML node line/column regions and logical locations. Missing properties point to their parent node and are labeled regionExact=false. Fingerprints combine relative source path, rule and logical location, remaining stable when unrelated lines move; changing indexed steps can change fingerprints. --baseline accepts a prior JSON report. --exceptions accepts a JSON array of fingerprint, explanation and expires (ISO date); --as-of controls expiry comparison, defaulting to the current UTC date. Expired exceptions never suppress failure thresholds. Reports retain suppressed findings and distinguish new, unchanged and resolved fingerprints. Composite steps and unpinned reusable workflow calls are covered by fixtures. No workflow is run, changed, or automatically trusted.

Local formatting, lint, strict types and regression tests pass. Public release completion requires the protected CI/CodeQL matrix, tagged artifacts and matching Forge catalog/detail deployment.

## Version 1.2.0: broader workflow review and portable baselines

Add five rules for privileged event chains, attacker-controlled checkout refs, unpinned container action digests, downloaded scripts piped into interpreters, and workflow-run artifact review. Add escaped standalone HTML reports with remediation guidance, a rule inventory, source-root-relative baselines, repeated exclusions, and opt-in failure thresholds for newly introduced findings.

## 1.3.0 acceptance

Bind reviewed exceptions to the configuration they approved and reopen changed findings under new-only review.

Copy both fingerprint and configuration_sha256 from a current JSON finding into each reviewed exception, together with explanation and expires. Any configuration-node change in that source file invalidates its bindings; comments, formatting and mapping-key order do not. The binding deliberately covers the full workflow configuration because permissions, events and neighboring steps affect trust. Legacy exceptions without a binding remain visible as unbound and do not suppress findings. Baselines now distinguish updated from unchanged, and --new-only evaluates new or updated findings. Hashes provide change evidence, not a signature or proof of safe workflow code. No actions are fetched or executed.

## Prior Gold Star review — October 17, 2026

Previously reviewed release: v1.3.2.
Check local workflow files for risky settings and keep a record of findings you have reviewed.

Logan considers this project complete. Continue fixes and maintenance, and consider good new ideas. The catalog records the reviewed release.

Definition: https://www.loganpendragonforge.com/open-source/?gold=1

## 1.4.0 report controls

Baseline comparisons now distinguish resolved findings from unverified findings in sources not scanned. Reports record scanned sources, excluded discovered sources and baseline sources omitted from this run. A missing or excluded file is not proof of resolution; use the same source root for comparable runs. Failure thresholds still apply only to findings actually scanned.

## 1.4.1 stdout regression acceptance

Exercise real closed stdout pipes with small and large reports, complete normal output, partial and zero descriptor writes, and in-memory streams. Verify status 2 without an ignored shutdown exception, unchanged source files, and existing report and output-file contracts.
