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


@pytest.mark.parametrize(
    "runner",
    [
        {"group": "shared", "labels": ["self-hosted", "linux"]},
        {"group": "shared", "labels": "self-hosted"},
        {"labels": ["Self-Hosted", "linux"]},
        ["Self-Hosted", "linux"],
    ],
)
def test_self_hosted_mapping_and_case_insensitive_labels(runner: object) -> None:
    findings = audit_document({"permissions": {}, "jobs": {"build": {"runs-on": runner}}})
    assert [finding.code for finding in findings] == ["WS005"]


@pytest.mark.parametrize("runner", [{"group": "shared"}, {"labels": "ubuntu-latest"}])
def test_runner_mapping_does_not_guess_host_type(runner: object) -> None:
    assert audit_document({"permissions": {}, "jobs": {"build": {"runs-on": runner}}}) == []


@pytest.mark.parametrize(
    "script,expected",
    [
        ('echo "github.event.issue.title"', False),
        ('echo "${{ env.SAFE_TITLE }}" # github.event.issue.title', False),
        ('echo "${{ github.event.issue.title }}"', True),
        ('echo "${{\ngithub.event.issue.body\n}}"', True),
    ],
)
def test_untrusted_shell_reference_requires_github_expression(script: str, expected: bool) -> None:
    findings = audit_document({"permissions": {}, "jobs": {"build": {"steps": [{"run": script}]}}})
    assert any(finding.code == "WS009" for finding in findings) is expected


def test_mapping_runner_and_expression_cli_roundtrip(tmp_path: Path) -> None:
    import json

    workflow = tmp_path / "workflow.yml"
    workflow.write_text(
        "permissions: {}\njobs:\n  build:\n    runs-on:\n"
        "      group: shared\n      labels: [self-hosted, linux]\n"
        "    steps:\n      - run: echo github.event.issue.title\n",
        encoding="utf-8",
    )
    output = tmp_path / "review.json"
    assert main([str(workflow), "--format", "json", "--output", str(output)]) == 0
    findings = json.loads(output.read_text())["reports"][0]["findings"]
    assert [finding["code"] for finding in findings] == ["WS005"]
    workflow.write_text(
        workflow.read_text().replace(
            "echo github.event.issue.title", "echo ${{ github.event.issue.title }}"
        ),
        encoding="utf-8",
    )
    sarif = tmp_path / "review.sarif"
    assert main([str(workflow), "--format", "sarif", "--output", str(sarif)]) == 1
    results = json.loads(sarif.read_text())["runs"][0]["results"]
    assert {finding["ruleId"] for finding in results} == {"WS005", "WS009"}
