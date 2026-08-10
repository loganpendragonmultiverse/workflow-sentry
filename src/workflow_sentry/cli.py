from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import SEVERITY_ORDER, audit_file, discover


def _markdown(reports: list[dict[str, object]]) -> str:
    lines = ["# Workflow Sentry report", ""]
    for report in reports:
        lines.extend(
            [
                f"## {report['source']}",
                "",
                "| Severity | Code | Location | Finding |",
                "|---|---|---|---|",
            ]
        )
        findings = report["findings"]
        assert isinstance(findings, list)
        if not findings:
            lines.append("| info | WS000 | workflow | No findings |")
        for finding in findings:
            assert isinstance(finding, dict)
            lines.append(
                f"| {finding['severity']} | {finding['code']} | `{finding['location']}` | {finding['message']} |"
            )
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit GitHub Actions workflows locally.")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="critical")
    args = parser.parse_args(argv)
    files = discover(args.paths)
    if not files:
        parser.error("no workflow YAML files found")
    reports = [audit_file(path) for path in files]
    rendered = (
        json.dumps({"schemaVersion": 1, "reports": reports}, indent=2)
        if args.format == "json"
        else _markdown(reports)
    )
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    threshold = SEVERITY_ORDER[args.fail_on]
    for report in reports:
        findings = report["findings"]
        assert isinstance(findings, list)
        if any(
            isinstance(item, dict) and SEVERITY_ORDER[str(item["severity"])] >= threshold
            for item in findings
        ):
            return 1
    return 0
