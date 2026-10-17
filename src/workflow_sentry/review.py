"""Source regions, SARIF and explicitly reviewed exceptions."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from typing import Any
from urllib.parse import quote

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


def configuration_digest(text: str) -> str:
    """Hash configuration nodes without copying source values into reports."""

    def encode(node: Node, active: set[int]) -> Any:
        if id(node) in active:
            raise ValueError("recursive YAML aliases are unsupported for review identity")
        active.add(id(node))
        try:
            if isinstance(node, MappingNode):
                pairs = [[encode(key, active), encode(value, active)] for key, value in node.value]
                return [
                    "mapping",
                    sorted(pairs, key=lambda pair: json.dumps(pair[0], ensure_ascii=False)),
                ]
            if isinstance(node, SequenceNode):
                return ["sequence", [encode(value, active) for value in node.value]]
            if isinstance(node, ScalarNode):
                return [node.tag, node.value]
            raise TypeError("unsupported YAML node")
        finally:
            active.remove(id(node))

    node = yaml.compose(text)
    encoded = encode(node, set()) if node is not None else None
    return hashlib.sha256(
        json.dumps(encoded, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


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
    digest = configuration_digest(text)
    regions = source_regions(text)
    for item in findings:
        location = item["location"]
        candidate = location
        while candidate not in regions and candidate:
            candidate = candidate.rsplit(".", 1)[0] if "." in candidate else ""
        item["region"] = regions.get(candidate, {"startLine": 1, "startColumn": 1})
        item["regionExact"] = location in regions
        item["configuration_sha256"] = digest
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
        binding = entry.get("configuration_sha256")
        if binding is not None and (
            not isinstance(binding, str) or re.fullmatch(r"[0-9a-f]{64}", binding) is None
        ):
            raise ValueError("configuration_sha256 must be a lowercase SHA-256 digest")
        if entry["fingerprint"] in allowed:
            raise ValueError("Duplicate exception fingerprint")
        allowed[entry["fingerprint"]] = {
            **entry,
            "expired": date.fromisoformat(entry["expires"]) < today,
        }
    old: set[str] = set()
    old_digests: dict[str, str | None] = {}
    for report in baseline.get("reports", []):
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise TypeError("baseline reports require findings arrays")
        for item in report["findings"]:
            if not isinstance(item, dict) or not isinstance(item.get("fingerprint"), str):
                raise TypeError(
                    "baseline findings require fingerprints from a current-format report"
                )
            old.add(item["fingerprint"])
            old_digests[item["fingerprint"]] = item.get("configuration_sha256")
    current: set[str] = set()
    updated: set[str] = set()
    for report in reports:
        for item in report["findings"]:
            fingerprint = item["fingerprint"]
            current.add(fingerprint)
            exception = allowed.get(fingerprint)
            state = "new"
            if fingerprint in old:
                state = (
                    "unchanged"
                    if old_digests.get(fingerprint) == item.get("configuration_sha256")
                    else "updated"
                )
                if state == "updated":
                    updated.add(fingerprint)
            item["baselineState"] = state
            exception_state = "none"
            if exception:
                if exception["expired"]:
                    exception_state = "expired"
                elif not exception.get("configuration_sha256"):
                    exception_state = "unbound"
                elif exception["configuration_sha256"] != item.get("configuration_sha256"):
                    exception_state = "configuration-changed"
                else:
                    exception_state = "active"
            item["exceptionState"] = exception_state
            item["suppressed"] = exception_state == "active"
            if exception:
                item["exception"] = exception
    return {
        "asOf": as_of,
        "new": sorted(current - old),
        "resolved": sorted(old - current),
        "unchanged": sorted((old & current) - updated),
        "updated": sorted(updated),
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
                                "uri": report["source"]
                                if report["source"].startswith("file:")
                                else quote(report["source"].replace("\\", "/"), safe="/.-_")
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
                    "configuration_sha256": item.get("configuration_sha256"),
                    "exceptionState": item.get("exceptionState", "none"),
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
