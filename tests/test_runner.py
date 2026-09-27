import subprocess
import sys

from bomwatch import runner


def test_missing_tool_returns_none():
    assert runner.run(["no-such-tool-bomwatch"]) is None


def test_success_returns_stdout():
    assert runner.run([sys.executable, "-c", "print('hi')"]) == "hi\n"


def test_failure_returns_none():
    assert runner.run([sys.executable, "-c", "raise SystemExit(2)"]) is None


def test_timeout_returns_none(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("x", 1)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner.run([sys.executable]) is None
