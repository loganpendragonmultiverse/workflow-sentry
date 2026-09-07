"""Source regions, SARIF and explicitly reviewed exceptions."""

from __future__ import annotations

import hashlib
from datetime import date
from typing import Any
from urllib.parse import quote

import yaml
from yaml.nodes import MappingNode, Node, SequenceNode


def source_regions(text: str) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}

    def walk(node: Node, path: str) -> None:
        result[path] = {
            "startLine": node.start_mark.line + 1,
            "startColumn": node.start_mark.column + 1,
        }
        if isinstance(node, MappingNode):
            for key, value in node.value:
                walk(value, f"{path}.{key.value}" if path else str(key.value))
        elif isinstance(node, SequenceNode):
            for index, value in enumerate(node.value):
                walk(value, f"{path}[{index}]")

    root = yaml.compose(text)
    if root is not None:
        walk(root, "")
    return result


def enrich(findings: list[dict[str, Any]], text: str, source: str) -> list[dict[str, Any]]:
    regions = source_regions(text)
    for item in findings:
        location = item["location"]
        candidate = location
        while candidate not in regions and candidate:
            candidate = candidate.rsplit(".", 1)[0] if "." in candidate else ""
        item["region"] = regions.get(candidate, {"startLine": 1, "startColumn": 1})
        item["regionExact"] = location in regions
        item["fingerprint"] = hashlib.sha256(
            f"{source}\0{item['code']}\0{location}".encode()
        ).hexdigest()
    return findings


def review(
    reports: list[dict[str, Any]], baseline: Any, exceptions: Any, as_of: str
) -> dict[str, Any]:
    today = date.fromisoformat(as_of)
    if not isinstance(baseline, dict) or not isinstance(baseline.get("reports", []), list):
        raise TypeError("baseline must contain a reports array")
    if not isinstance(exceptions, list):
        raise TypeError("exceptions must be an array")
    allowed: dict[str, dict[str, Any]] = {}
    for entry in exceptions:
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(k), str) or not entry[k].strip()
            for k in ("fingerprint", "explanation", "expires")
        ):
            raise ValueError("Each exception needs fingerprint, explanation and expires strings")
        if entry["fingerprint"] in allowed:
            raise ValueError("Duplicate exception fingerprint")
        allowed[entry["fingerprint"]] = {
            **entry,
            "expired": date.fromisoformat(entry["expires"]) < today,
        }
    old: set[str] = set()
    for report in baseline.get("reports", []):
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise TypeError("baseline reports require findings arrays")
        for item in report["findings"]:
            if not isinstance(item, dict) or not isinstance(item.get("fingerprint"), str):
                raise TypeError(
                    "baseline findings require fingerprints from a current-format report"
                )
            old.add(item["fingerprint"])
    current: set[str] = set()
    for report in reports:
        for item in report["findings"]:
            fingerprint = item["fingerprint"]
            current.add(fingerprint)
            exception = allowed.get(fingerprint)
            item["baselineState"] = "unchanged" if fingerprint in old else "new"
            item["suppressed"] = bool(exception and not exception["expired"])
            if exception:
                item["exception"] = exception
    return {
        "asOf": as_of,
        "new": sorted(current - old),
        "resolved": sorted(old - current),
        "unchanged": sorted(old & current),
        "exceptions": list(allowed.values()),
        "unmatchedExceptions": sorted(allowed.keys() - current),
    }


def sarif(reports: list[dict[str, Any]], comparison: dict[str, Any]) -> dict[str, Any]:
    rules = {item["code"]: item["message"] for r in reports for item in r["findings"]}
    results = []
    for report in reports:
        for item in report["findings"]:
            result: dict[str, Any] = {
                "ruleId": item["code"],
                "message": {"text": item["message"]},
                "level": "error"
                if item["severity"] in ("critical", "high")
                else "note"
                if item["severity"] in ("info", "low")
                else "warning",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": quote(report["source"].replace("\\", "/"), safe="/.-_")
                            },
                            "region": item["region"],
                        }
                    }
                ],
                "partialFingerprints": {"workflowSentry/v1": item["fingerprint"]},
                "baselineState": item.get("baselineState", "new"),
                "properties": {
                    "logicalLocation": item["location"],
                    "regionExact": item["regionExact"],
                },
            }
            if item.get("suppressed"):
                result["suppressions"] = [
                    {
                        "kind": "external",
                        "status": "accepted",
                        "justification": item["exception"]["explanation"],
                    }
                ]
            results.append(result)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Workflow Sentry",
                        "rules": [
                            {"id": code, "shortDescription": {"text": message}}
                            for code, message in sorted(rules.items())
                        ],
                    }
                },
                "results": results,
                "properties": {"comparison": comparison},
            }
        ],
    }
