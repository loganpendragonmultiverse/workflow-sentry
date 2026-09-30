"""Additional value-free static checks and remediation guidance."""

from __future__ import annotations

import re
from typing import Any, cast

GUIDANCE = {
    "WS001": "Declare an explicit permissions block; use an empty mapping when no token access is needed.",
    "WS002": "Replace write-all with the minimum named permissions required by each job.",
    "WS003": "Review each write permission and scope it to the job that needs it.",
    "WS004": "Do not execute pull-request code in a privileged pull_request_target workflow.",
    "WS005": "Isolate self-hosted runners and prevent untrusted code from reaching persistent hosts.",
    "WS006": "Pass only the explicitly required secrets to reusable workflows.",
    "WS007": "Pin remote actions and reusable workflows to a reviewed full commit SHA.",
    "WS008": "Set persist-credentials: false unless later authenticated Git operations are required.",
    "WS009": "Pass event text through a quoted environment variable instead of interpolating it into shell source.",
    "WS010": "Avoid checking out an untrusted head in a privileged workflow; separate trusted orchestration.",
    "WS011": "Review workflow_run trust boundaries and avoid executing untrusted artifacts or head commits.",
    "WS012": "Pin container actions to an immutable sha256 digest after reviewing their source.",
    "WS013": "Download and verify scripts separately before any explicitly reviewed execution.",
    "WS014": "Treat artifacts from preceding workflows as untrusted input and verify them before use.",
}


def trigger_names(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {x for x in value if isinstance(x, str)}
    return set(value) if isinstance(value, dict) else set()


def audit_advanced(document: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    result: list[tuple[str, str, str, str]] = []
    triggers = trigger_names(document.get("on", cast(dict[object, Any], document).get(True)))
    privileged = bool(triggers & {"pull_request_target", "workflow_run"})
    if "workflow_run" in triggers:
        result.append(
            (
                "high",
                "WS011",
                "on.workflow_run",
                "workflow_run can cross an untrusted-to-privileged execution boundary.",
            )
        )
    jobs = document.get("jobs", {})
    if not isinstance(jobs, dict):
        return result
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            location = f"jobs.{name}.steps[{i}]"
            uses = step.get("uses")
            if isinstance(uses, str):
                if uses.startswith("docker://") and not re.fullmatch(
                    r"docker://[^\s]+@sha256:[0-9a-fA-F]{64}", uses
                ):
                    result.append(
                        (
                            "medium",
                            "WS012",
                            location + ".uses",
                            "Container action is not pinned to a full sha256 digest.",
                        )
                    )
                if privileged and uses.startswith("actions/checkout@"):
                    options = step.get("with", {})
                    ref = options.get("ref", "") if isinstance(options, dict) else ""
                    if isinstance(ref, str) and any(
                        x in ref
                        for x in [
                            "github.event.pull_request.head",
                            "github.event.workflow_run.head",
                            "github.head_ref",
                        ]
                    ):
                        result.append(
                            (
                                "critical",
                                "WS010",
                                location + ".with.ref",
                                "Privileged workflow checks out an untrusted event head.",
                            )
                        )
                if "workflow_run" in triggers and uses.startswith("actions/download-artifact@"):
                    result.append(
                        (
                            "high",
                            "WS014",
                            location + ".uses",
                            "Privileged workflow consumes artifacts from another run.",
                        )
                    )
            run = step.get("run")
            if isinstance(run, str) and re.search(
                r"\b(?:curl|wget)\b[^\n]*\|\s*(?:(?:sudo|env)\s+)?(?:sh|bash|zsh|python[\d.]*)\b",
                run,
            ):
                result.append(
                    (
                        "high",
                        "WS013",
                        location + ".run",
                        "Shell executes a downloaded script through a pipeline.",
                    )
                )
    return result
