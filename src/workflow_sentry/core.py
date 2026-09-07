from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from .review import enrich

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
UNTRUSTED_EXPRESSIONS = (
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
)


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    location: str
    message: str


def _mapping(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _sequence(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _check_permissions(value: object, location: str) -> list[Finding]:
    if value is None:
        return [
            Finding("medium", "WS001", location, "No explicit least-privilege permissions block.")
        ]
    if value == "write-all":
        return [Finding("critical", "WS002", location, "Workflow grants write-all permissions.")]
    findings: list[Finding] = []
    for name, access in _mapping(value).items():
        if access == "write":
            if name in {"actions", "contents", "id-token", "packages"}:
                severity = "high"
            elif name == "security-events":
                severity = "info"
            else:
                severity = "medium"
            findings.append(
                Finding(severity, "WS003", f"{location}.{name}", f"Permission {name} is writable.")
            )
    return findings


def _is_immutable_reference(reference: str) -> bool:
    if reference.startswith(("./", "docker://")):
        return True
    if "@" not in reference:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", reference.rsplit("@", 1)[1]))


def audit_document(document: dict[str, Any]) -> list[Finding]:
    if _mapping(document.get("runs")).get("using") == "composite":
        proxy = {
            "permissions": {},
            "jobs": {"composite": {"steps": _mapping(document["runs"]).get("steps", [])}},
        }
        return [
            Finding(
                f.severity,
                f.code,
                f.location.replace("jobs.composite.steps", "runs.steps"),
                f.message,
            )
            for f in audit_document(proxy)
        ]
    findings = _check_permissions(document.get("permissions"), "permissions")
    triggers = document.get("on", cast(dict[object, Any], document).get(True))
    trigger_names = {triggers} if isinstance(triggers, str) else set(_mapping(triggers))
    if "pull_request_target" in trigger_names:
        findings.append(
            Finding(
                "high",
                "WS004",
                "on.pull_request_target",
                "Privileged pull_request_target trigger requires manual review.",
            )
        )

    for job_name, raw_job in _mapping(document.get("jobs")).items():
        job = _mapping(raw_job)
        location = f"jobs.{job_name}"
        if isinstance(job.get("uses"), str) and not _is_immutable_reference(job["uses"]):
            findings.append(
                Finding(
                    "medium",
                    "WS007",
                    f"{location}.uses",
                    "Reusable workflow is not pinned to a full commit SHA.",
                )
            )
        if "permissions" in job:
            findings.extend(_check_permissions(job.get("permissions"), f"{location}.permissions"))
        runs_on = job.get("runs-on")
        runners = [runs_on] if isinstance(runs_on, str) else _sequence(runs_on)
        if "self-hosted" in runners:
            findings.append(
                Finding("high", "WS005", f"{location}.runs-on", "Job uses a self-hosted runner.")
            )
        if job.get("secrets") == "inherit":
            findings.append(
                Finding(
                    "high",
                    "WS006",
                    f"{location}.secrets",
                    "Reusable workflow inherits every caller secret.",
                )
            )

        for index, raw_step in enumerate(_sequence(job.get("steps"))):
            step = _mapping(raw_step)
            step_location = f"{location}.steps[{index}]"
            uses = step.get("uses")
            if isinstance(uses, str) and not _is_immutable_reference(uses):
                findings.append(
                    Finding(
                        "medium",
                        "WS007",
                        f"{step_location}.uses",
                        "Action is not pinned to a full commit SHA.",
                    )
                )
            if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                persist = _mapping(step.get("with")).get("persist-credentials")
                if persist is not False and str(persist).lower() != "false":
                    findings.append(
                        Finding(
                            "low",
                            "WS008",
                            f"{step_location}.with",
                            "Checkout credentials remain available to later steps.",
                        )
                    )
            run = step.get("run")
            if isinstance(run, str) and any(expr in run for expr in UNTRUSTED_EXPRESSIONS):
                findings.append(
                    Finding(
                        "critical",
                        "WS009",
                        f"{step_location}.run",
                        "Shell script interpolates untrusted event text directly.",
                    )
                )
    return findings


def audit_file(path: Path, *, source: str | None = None) -> dict[str, Any]:
    raw = path.read_bytes()
    loaded = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError("workflow root must be a mapping")
    findings = audit_document(cast(dict[str, Any], loaded))
    counts = {
        severity: sum(item.severity == severity for item in findings) for severity in SEVERITY_ORDER
    }
    return {
        "schemaVersion": 1,
        "source": source or path.name,
        "sourceSha256": hashlib.sha256(raw).hexdigest(),
        "counts": counts,
        "findings": enrich(
            [asdict(item) for item in findings], raw.decode("utf-8"), source or path.name
        ),
    }


def discover(paths: list[Path]) -> list[Path]:
    discovered: set[Path] = set()
    for path in paths:
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
            discovered.add(path)
        elif path.is_dir():
            discovered.update(path.rglob("*.yml"))
            discovered.update(path.rglob("*.yaml"))
    return sorted(discovered)
