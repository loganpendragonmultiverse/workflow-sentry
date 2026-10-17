import json
from pathlib import Path

import pytest

from workflow_sentry.cli import main
from workflow_sentry.core import audit_file
from workflow_sentry.review import configuration_digest, review


def fixture(action):
    return (
        "on: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: "
        + action
        + "\n"
    )


def test_changed_action_revokes_exception_and_new_only_rechecks(tmp_path: Path, capsys):
    path = tmp_path / "ci.yml"
    path.write_text(fixture("reviewed/action@v1"))
    first = audit_file(path, source="ci.yml")
    item = first["findings"][0]
    ex = tmp_path / "exceptions.json"
    base = tmp_path / "baseline.json"
    ex.write_text(
        json.dumps(
            [
                {
                    "fingerprint": item["fingerprint"],
                    "configuration_sha256": item["configuration_sha256"],
                    "explanation": "Reviewed original configuration",
                    "expires": "2027-01-01",
                }
            ]
        )
    )
    base.write_text(json.dumps({"reports": [first]}))
    args = [
        str(path),
        "--root",
        str(tmp_path),
        "--exceptions",
        str(ex),
        "--baseline",
        str(base),
        "--new-only",
        "--fail-on",
        "medium",
        "--as-of",
        "2026-10-17",
        "--format",
        "json",
    ]
    assert main(args) == 0
    capsys.readouterr()
    path.write_text("# comment only\n" + fixture("reviewed/action@v1"))
    assert main(args) == 0
    capsys.readouterr()
    path.write_text(fixture("different/action@main"))
    assert main(args) == 1
    result = json.loads(capsys.readouterr().out)
    finding = result["reports"][0]["findings"][0]
    assert finding["fingerprint"] == item["fingerprint"]
    assert not finding["suppressed"] and finding["exceptionState"] == "configuration-changed"
    assert finding["baselineState"] == "updated" and result["comparison"]["updated"]
    assert "different/action" not in json.dumps(result)


def test_mapping_order_whitespace_and_legacy_exception():
    assert configuration_digest("a: 1\nb: [x,y]\n") == configuration_digest(
        "# comment\nb: [x, y]\na: 1\n"
    )
    assert configuration_digest("")
    item = {"fingerprint": "f", "configuration_sha256": "a" * 64}
    report = {"findings": [item]}
    review(
        [report],
        {},
        [{"fingerprint": "f", "explanation": "legacy", "expires": "2027-01-01"}],
        "2026-10-17",
    )
    assert item["exceptionState"] == "unbound" and not item["suppressed"]
    with pytest.raises(ValueError, match="configuration_sha256"):
        review(
            [report],
            {},
            [
                {
                    "fingerprint": "f",
                    "configuration_sha256": "bad",
                    "explanation": "invalid",
                    "expires": "2027-01-01",
                }
            ],
            "2026-10-17",
        )
    with pytest.raises(ValueError, match="recursive"):
        configuration_digest("a: &loop [*loop]")
