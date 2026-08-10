from pathlib import Path

import pytest

from workflow_sentry.cli import main
from workflow_sentry.core import audit_document, audit_file, discover


def test_flags_dangerous_workflow() -> None:
    findings = audit_document(
        {
            "on": {"pull_request_target": {}},
            "permissions": "write-all",
            "jobs": {
                "build": {
                    "runs-on": "self-hosted",
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {"run": "echo ${{ github.event.issue.title }}"},
                    ],
                }
            },
        }
    )
    assert {finding.code for finding in findings} == {
        "WS002",
        "WS004",
        "WS005",
        "WS007",
        "WS008",
        "WS009",
    }


def test_accepts_sha_pinned_minimal_workflow() -> None:
    findings = audit_document(
        {
            "permissions": {"contents": "read"},
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"uses": "owner/action@" + "a" * 40}],
                }
            },
        }
    )
    assert findings == []


def test_reports_writable_job_permission_and_inherited_secrets() -> None:
    findings = audit_document(
        {
            "permissions": {},
            "jobs": {"call": {"permissions": {"contents": "write"}, "secrets": "inherit"}},
        }
    )
    assert [finding.code for finding in findings] == ["WS003", "WS006"]


def test_audit_file_and_discovery(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow.yml"
    workflow.write_text("permissions: {}\njobs: {}\n", encoding="utf-8")
    report = audit_file(workflow)
    assert report["source"] == "workflow.yml"
    assert len(str(report["sourceSha256"])) == 64
    assert discover([tmp_path]) == [workflow]


def test_cli_json_output_and_failure(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow.yaml"
    workflow.write_text("permissions: write-all\njobs: {}\n", encoding="utf-8")
    output = tmp_path / "report.json"
    assert (
        main([str(workflow), "--format", "json", "--output", str(output), "--fail-on", "high"]) == 1
    )
    assert '"WS002"' in output.read_text(encoding="utf-8")


def test_invalid_root_raises(tmp_path: Path) -> None:
    workflow = tmp_path / "bad.yml"
    workflow.write_text("- item\n", encoding="utf-8")
    with pytest.raises(TypeError, match="mapping"):
        audit_file(workflow)


def test_cli_markdown_clean_and_missing_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workflow = tmp_path / "clean.yml"
    workflow.write_text("permissions: {}\njobs: {}\n", encoding="utf-8")
    assert main([str(workflow), "--fail-on", "low"]) == 0
    assert "No findings" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main([str(tmp_path / "missing")])
