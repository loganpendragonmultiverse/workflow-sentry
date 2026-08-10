# Development handoff

Workflow Sentry is a read-only, local static analyzer for GitHub Actions. Version 1 deliberately avoids remote action resolution, automatic rewrites, secret access, and claims of complete workflow safety. Rule codes and value-free output are public contracts; additions require adversarial fixtures and must not echo secrets or expression values.
