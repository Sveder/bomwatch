import runpy

import pytest

from bomwatch import __version__
from bomwatch.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"bomwatch {__version__}"


def test_no_command_is_usage_error(capsys):
    assert main([]) == 2
    assert "usage: bomwatch" in capsys.readouterr().err


def test_module_entry_point(monkeypatch):
    monkeypatch.setattr("sys.argv", ["bomwatch"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("bomwatch", run_name="__main__")
    assert exc.value.code == 2
