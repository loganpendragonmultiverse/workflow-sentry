import io
import json
import os
import subprocess
import sys

import pytest

from workflow_sentry.cli import _write_stdout


def invocation(tmp_path, large, format_name="json"):
    source = tmp_path / "workflow.yml"
    steps = [{"run": "echo ${{ github.event.issue.body }}"}] * (100 if large else 1)
    source.write_text(
        json.dumps(
            {
                "on": "push",
                "permissions": {},
                "jobs": {"review": {"runs-on": "ubuntu-latest", "steps": steps}},
            }
        ),
        encoding="utf-8",
    )
    args = [source, "--format", format_name]
    return source, args


@pytest.mark.parametrize("large", [False, True])
@pytest.mark.parametrize("format_name", ["json", "sarif"])
def test_normal_stdout_is_complete_and_preserves_input(tmp_path, large, format_name):
    source, args = invocation(tmp_path, large, format_name)
    before = source.read_bytes()
    result = subprocess.run(
        [sys.executable, "-m", "workflow_sentry", *map(str, args)], capture_output=True, check=False
    )
    assert result.returncode == 1, result.stderr
    assert not result.stderr
    assert source.read_bytes() == before
    assert len(result.stdout) > 8192 if large else len(result.stdout) < 8192
    assert json.loads(result.stdout)


@pytest.mark.parametrize("large", [False, True])
@pytest.mark.parametrize("format_name", ["json", "sarif"])
def test_closed_stdout_pipe_returns_two_without_shutdown_warning(tmp_path, large, format_name):
    source, args = invocation(tmp_path, large, format_name)
    before = source.read_bytes()
    reader, writer = os.pipe()
    os.close(reader)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "workflow_sentry", *map(str, args)],
            stdout=writer,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        os.close(writer)
    assert result.returncode == 2, result.stderr
    assert b"error:" in result.stderr
    assert b"Exception ignored" not in result.stderr
    assert b"Traceback" not in result.stderr
    assert source.read_bytes() == before
    assert not list(tmp_path.glob("*.report"))


def test_in_memory_stdout_is_not_replaced_or_closed(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    _write_stdout("Complete Ω report\n")
    assert sys.stdout is stream and not stream.closed
    assert stream.getvalue() == "Complete Ω report\n"
    stream.write("still open")


@pytest.mark.parametrize("zero", [False, True])
def test_descriptor_short_and_zero_writes(monkeypatch, zero):
    class Output:
        encoding = "utf-8"
        errors = "strict"

        def fileno(self):
            return 123

    stream = Output()
    received = bytearray()

    def write(descriptor, remaining):
        assert descriptor == 123
        if zero:
            return 0
        received.extend(remaining[:7])
        return min(7, len(remaining))

    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(os, "write", write)
    if zero:
        with pytest.raises(OSError, match="no report bytes"):
            _write_stdout("Complete Ω report\n")
    else:
        _write_stdout("Complete Ω report\n")
        assert received == "Complete Ω report\n".encode()
    assert sys.stdout is stream


def test_closed_pipe_rule_inventory_returns_two():
    reader, writer = os.pipe()
    os.close(reader)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "workflow_sentry", "--list-rules"],
            stdout=writer,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        os.close(writer)
    assert result.returncode == 2
    assert b"error:" in result.stderr and b"Exception ignored" not in result.stderr
