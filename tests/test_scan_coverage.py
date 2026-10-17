import json

from workflow_sentry.cli import main
from workflow_sentry.core import audit_file
from workflow_sentry.review import review


def test_partial_scan_never_claims_resolution(tmp_path, capsys):
    a, b = tmp_path / "a.yml", tmp_path / "b.yml"
    for p in (a, b):
        p.write_text("permissions: write-all\njobs: {}\n", encoding="utf-8")
    baseline = {"reports": [audit_file(p, source=p.name) for p in (a, b)]}
    saved = tmp_path / "baseline.json"
    saved.write_text(json.dumps(baseline), encoding="utf-8")
    assert (
        main(
            [
                str(tmp_path),
                "--root",
                str(tmp_path),
                "--exclude",
                "b.yml",
                "--baseline",
                str(saved),
                "--new-only",
                "--format",
                "json",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)["comparison"]
    assert result["resolved"] == []
    assert result["unverified"] == [baseline["reports"][1]["findings"][0]["fingerprint"]]
    assert result["coverage"] == {
        "scannedSources": ["a.yml"],
        "unscannedBaselineSources": ["b.yml"],
        "excludedSources": ["b.yml"],
    }
    a.write_text("permissions: {}\njobs: {}\n", encoding="utf-8")
    checked = review([audit_file(a, source="a.yml")], baseline, [], "2026-10-17")
    assert checked["resolved"] == [baseline["reports"][0]["findings"][0]["fingerprint"]]
    assert checked["unverified"] == result["unverified"]


def test_legacy_unknown_source_is_unverified():
    result = review([], {"reports": [{"findings": [{"fingerprint": "legacy"}]}]}, [], "2026-10-17")
    assert result["resolved"] == []
    assert result["unverified"] == ["legacy"]


def test_coverage_is_visible_in_sarif_and_html(tmp_path, capsys):
    source = tmp_path / "ci.yml"
    source.write_text("permissions: {}\njobs: {}\n", encoding="utf-8")
    assert main([str(source), "--root", str(tmp_path), "--format", "sarif"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["runs"][0]["properties"]["comparison"]["coverage"]["scannedSources"] == ["ci.yml"]
    assert main([str(source), "--root", str(tmp_path), "--format", "html"]) == 0
    html = capsys.readouterr().out
    assert "not confirmed resolved" in html
    assert "ci.yml" in html
