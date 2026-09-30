from __future__ import annotations

import argparse
import fnmatch
import json
import os as os  # noqa: PLC0414 - retained module attribute used by compatibility tests
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .advanced import GUIDANCE
from .core import SEVERITY_ORDER, audit_file, discover
from .presentation import html_report
from .review import review, sarif


def _source_location(path: Path) -> str:
    try:
        return Path(os.path.relpath(path)).as_posix()
    except ValueError:
        return path.resolve().as_uri()


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
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument(
        "--root", type=Path, help="Stable source root for portable baseline fingerprints."
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude a source-relative glob; repeat as needed.",
    )
    parser.add_argument(
        "--new-only",
        action="store_true",
        help="Apply the failure threshold only to new baseline findings.",
    )
    parser.add_argument(
        "--format", choices=("json", "markdown", "sarif", "html"), default="markdown"
    )
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--exceptions", type=Path)
    parser.add_argument("--as-of", default=datetime.now(timezone.utc).date().isoformat())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="critical")
    args = parser.parse_args(argv)
    if args.list_rules:
        print(json.dumps(GUIDANCE, indent=2))
        return 0
    if args.new_only and not args.baseline:
        print("error: --new-only requires --baseline", file=sys.stderr)
        return 2
    files = discover(args.paths)
    try:
        sources = {
            path: path.resolve().relative_to(args.root.resolve()).as_posix()
            if args.root
            else _source_location(path)
            for path in files
        }
    except ValueError:
        print("error: a source is outside --root", file=sys.stderr)
        return 2
    files = [
        path
        for path in files
        if not any(fnmatch.fnmatchcase(sources[path], pattern) for pattern in args.exclude)
    ]
    if not files:
        parser.error("no workflow YAML files found after exclusions")
    try:
        if args.output and args.output.exists():
            raise ValueError("output already exists")
        reports = [audit_file(path, source=sources[path]) for path in files]
        baseline = json.loads(args.baseline.read_text(encoding="utf-8")) if args.baseline else {}
        exceptions = (
            json.loads(args.exceptions.read_text(encoding="utf-8")) if args.exceptions else []
        )
        comparison = review(reports, baseline, exceptions, args.as_of)
        rendered = (
            html_report(reports, comparison)
            if args.format == "html"
            else json.dumps(sarif(reports, comparison), indent=2)
            if args.format == "sarif"
            else json.dumps(
                {"schemaVersion": 1, "reports": reports, "comparison": comparison}, indent=2
            )
            if args.format == "json"
            else _markdown(reports)
            + "\n## Review comparison\n\n```json\n"
            + json.dumps(comparison, indent=2)
            + "\n```\n"
        )
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    threshold = SEVERITY_ORDER[args.fail_on]
    for report in reports:
        findings = report["findings"]
        assert isinstance(findings, list)
        if any(
            isinstance(item, dict)
            and not item.get("suppressed")
            and (not args.new_only or item.get("baselineState") == "new")
            and SEVERITY_ORDER[str(item["severity"])] >= threshold
            for item in findings
        ):
            return 1
    return 0
