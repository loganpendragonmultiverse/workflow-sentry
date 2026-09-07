import copy
import json
from pathlib import Path

import pytest

from workflow_sentry.cli import main
from workflow_sentry.core import audit_file
from workflow_sentry.review import review, sarif


def test_cross_drive_source_uri(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from workflow_sentry import cli

    source = tmp_path / "space name.yml"
    source.write_text("permissions: write-all", encoding="utf-8")

    def different_drive(path: Path) -> str:
        raise ValueError("different drives")

    monkeypatch.setattr(cli.os.path, "relpath", different_drive)
    assert cli._source_location(source) == source.as_uri()
    report = audit_file(source, source=cli._source_location(source))
    uri = sarif([report], {})["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == source.as_uri()


def test_regions_fingerprints_baseline_expiry_and_sarif(tmp_path: Path) -> None:
    source = tmp_path / "ci.yml"
    text = "on: push\npermissions: {}\njobs:\n  build:\n    steps:\n      - uses: owner/action@v1\n"
    source.write_text(text, encoding="utf-8")
    first = audit_file(source)
    item = first["findings"][0]
    assert item["region"] == {"startLine": 6, "startColumn": 15}
    source.write_text("# new comment\n" + text, encoding="utf-8")
    current = audit_file(source)
    assert current["findings"][0]["fingerprint"] == item["fingerprint"]
    assert current["findings"][0]["region"]["startLine"] == 7
    exceptions = [
        {
            "fingerprint": item["fingerprint"],
            "explanation": "Pinned upgrade is reviewed for next sprint",
            "expires": "2026-09-08",
        }
    ]
    comparison = review([current], {"reports": [first]}, exceptions, "2026-09-07")
    assert comparison["unchanged"] == [item["fingerprint"]]
    assert current["findings"][0]["suppressed"]
    result = sarif([current], comparison)["runs"][0]["results"][0]
    assert result["suppressions"][0]["kind"] == "external"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    review([current], {}, exceptions, "2026-09-09")
    assert not current["findings"][0]["suppressed"]
    assert review([], {"reports": [first]}, [], "2026-09-07")["resolved"] == [item["fingerprint"]]


@pytest.mark.parametrize(
    "baseline,exceptions",
    [
        ([], []),
        ({}, {}),
        ({}, [{}]),
        ({"reports": [None]}, []),
        ({"reports": [{"findings": [None]}]}, []),
    ],
)
def test_invalid_review_contract(baseline: object, exceptions: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        review([], baseline, exceptions, "2026-09-07")


def test_composite_reusable_and_cli_errors(tmp_path: Path) -> None:
    composite = tmp_path / "action.yml"
    composite.write_text(
        "runs:\n  using: composite\n  steps:\n    - uses: owner/action@v1\n", encoding="utf-8"
    )
    report = audit_file(composite)
    assert len(report["findings"]) == 1
    assert report["findings"][0]["location"] == "runs.steps[0].uses"
    reusable = tmp_path / "reusable.yml"
    reusable.write_text(
        "on: workflow_call\npermissions: {}\njobs:\n  call:\n    uses: owner/repo/.github/workflows/build.yml@main\n    secrets: inherit\n",
        encoding="utf-8",
    )
    assert {f["code"] for f in audit_file(reusable)["findings"]} == {"WS006", "WS007"}
    out = tmp_path / "result.sarif"
    assert main([str(composite), "--format", "sarif", "--output", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert main([str(composite), "--output", str(out)]) == 2
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"reports": []}), encoding="utf-8")
    exception = tmp_path / "exceptions.json"
    exception.write_text("[]", encoding="utf-8")
    assert main([str(composite), "--baseline", str(baseline), "--exceptions", str(exception)]) == 0
    entry = {"fingerprint": "x", "explanation": "reviewed", "expires": "2026-09-07"}
    with pytest.raises(ValueError, match="Duplicate"):
        review([], {}, [entry, copy.deepcopy(entry)], "2026-09-07")
