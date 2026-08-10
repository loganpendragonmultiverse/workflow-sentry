# Workflow Sentry

Workflow Sentry audits GitHub Actions YAML locally for high-impact security risks before a workflow is merged.

It checks explicit token permissions, immutable action references, `pull_request_target`, self-hosted runners, inherited reusable-workflow secrets, checkout credential persistence, and direct shell interpolation of untrusted event text. Required `security-events: write` access is surfaced as informational evidence rather than treated as a defect. Reports contain rule locations and classifications, not repository secrets or workflow values.

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

Supported on Python 3.10+ for Windows, macOS, and Linux. Current release: **v1.0.0**.

## Development

```bash
python -m pip install -e ".[dev]"
ruff format --check . && ruff check .
mypy src
pytest
python -m build
```

Security reports belong in `SECURITY.md` through the organization policy. Contributions are reviewed through pull requests. Licensed under MIT.
