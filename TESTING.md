# Testing

Run `ruff format --check .`, `ruff check .`, `mypy src`, `pytest`, `python -m build`, and `python -m pip_audit .`. Tests cover privileged triggers, permissions, runner trust, immutable references, untrusted shell interpolation, discovery, hashing, CLI output, and invalid YAML roots.
