import json
from pathlib import Path

import pytest

from workflow_sentry.cli import main
from workflow_sentry.core import audit_document


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("'github.event.issue.title'", False),
        ("format('github.event.issue.title: {0}', env.SAFE_TEXT)", False),
        ("'can''t use github.event.issue.title'", False),
        ("github['event']['issue']['title']", True),
        ("github.event['issue'].body", True),
        ("github [ 'event' ] . issue [ 'title' ]", True),
        ("format('{0}', github['event'].comment.body)", True),
        ("format('}}', github.event.issue.title)", True),
        ("github.event.issue.title_suffix", False),
        ("env.SAFE_TEXT", False),
        ("github[inputs.key].issue.title", False),
        ("fromJSON(env.JSON).github.event.issue.title", False),
    ],
)
def test_static_event_paths_and_quoted_literals(expression: str, expected: bool) -> None:
    found = audit_document(
        {
            "permissions": {},
            "jobs": {"check": {"steps": [{"run": "echo ${{ " + expression + " }}"}]}},
        }
    )
    assert any(finding.code == "WS009" for finding in found) is expected


def test_expression_literal_and_index_cli_thresholds(tmp_path: Path) -> None:
    source = tmp_path / "workflow.yml"
    original = "permissions: {}\njobs:\n  check:\n    steps:\n      - run: \"echo ${{ 'github.event.issue.title' }}\"\n"
    source.write_text(original, encoding="utf-8")
    report = tmp_path / "literal.json"
    assert main([str(source), "--format", "json", "--output", str(report)]) == 0
    assert json.loads(report.read_text(encoding="utf-8"))["reports"][0]["findings"] == []
    source.write_text(
        original.replace("'github.event.issue.title'", "github['event']['issue']['title']"),
        encoding="utf-8",
    )
    expected_source = source.read_bytes()
    report = tmp_path / "indexed.sarif"
    assert main([str(source), "--format", "sarif", "--output", str(report)]) == 1
    result = json.loads(report.read_text(encoding="utf-8"))["runs"][0]["results"]
    assert [finding["ruleId"] for finding in result] == ["WS009"]
    assert source.read_bytes() == expected_source


@pytest.mark.parametrize("tail", ["", " }}", "' }} ${{ github.event.issue.title }}"])
def test_long_escaped_quote_sequences_remain_bounded(tail: str) -> None:
    script = "echo ${{ '" + "''" * 20000 + tail
    findings = audit_document({"permissions": {}, "jobs": {"check": {"steps": [{"run": script}]}}})
    assert any(item.code == "WS009" for item in findings) is tail.startswith("' }}")
