import json

import pytest

from bomwatch import cli, collectors, vulns
from bomwatch.model import Package


@pytest.fixture(name="installed")
def fixture_installed(monkeypatch):
    state = {"pkgs": [Package("pip", "jinja2", "2.10", "/e")]}

    def fake_collect_all(_roots=None, only=None):
        status = {"pip": "ok", "npm": "skipped" if only else "ok"}
        return list(state["pkgs"]), status

    monkeypatch.setattr(collectors, "collect_all", fake_collect_all)
    return state


@pytest.fixture(name="osv")
def fixture_osv(monkeypatch):
    calls = []

    def lookup(packages, system=None):  # pylint: disable=unused-argument
        calls.append(list(packages))
        return {p: ["GHSA-1"] for p in packages if p.version == "2.10"}

    monkeypatch.setattr(vulns, "lookup", lookup)
    monkeypatch.setattr(vulns, "summaries", lambda ids: {"GHSA-1": "sandbox escape"})
    return calls


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, capsys.readouterr()


def test_diff_vulns_checks_only_new_versions(installed, osv, tmp_path, capsys):
    installed["pkgs"] = [Package("pip", "safe", "1.0", "/e")]
    run(capsys, "scan", "--state-dir", str(tmp_path))
    installed["pkgs"] = [
        Package("pip", "safe", "1.0", "/e"),
        Package("pip", "jinja2", "2.10", "/e"),
    ]
    run(capsys, "scan", "--state-dir", str(tmp_path))
    code, out = run(capsys, "diff", "--vulns", "--state-dir", str(tmp_path))
    assert code == 4
    assert osv[-1] == [Package("pip", "jinja2", "2.10", "/e")]
    assert "! pip jinja2 2.10 (/e)" in out.out and "sandbox escape" in out.out
    code, out = run(capsys, "diff", "--vulns", "--json", "--state-dir", str(tmp_path))
    assert code == 4
    assert json.loads(out.out)["vulns"][0]["vulns"][0]["id"] == "GHSA-1"


@pytest.mark.usefixtures("osv")
def test_vulns_command(installed, tmp_path, capsys):
    code, out = run(capsys, "vulns", "--state-dir", str(tmp_path))
    assert code == 1 and "no snapshot yet" in out.err
    run(capsys, "scan", "--state-dir", str(tmp_path))
    code, out = run(capsys, "vulns", "--state-dir", str(tmp_path))
    assert code == 4 and "GHSA-1" in out.out
    code, out = run(
        capsys, "vulns", "--json", "--no-details", "--state-dir", str(tmp_path)
    )
    assert json.loads(out.out)[0]["package"]["name"] == "jinja2"
    installed["pkgs"] = []
    run(capsys, "scan", "--state-dir", str(tmp_path))
    code, out = run(capsys, "vulns", "--state-dir", str(tmp_path))
    assert code == 0 and "no known vulnerabilities" in out.out


@pytest.mark.usefixtures("installed")
def test_export(tmp_path, capsys):
    run(capsys, "scan", "--state-dir", str(tmp_path))
    code, out = run(capsys, "export", "--state-dir", str(tmp_path))
    assert code == 0
    assert json.loads(out.out)["components"][0]["purl"] == "pkg:pypi/jinja2@2.10"
    target = tmp_path / "sbom.spdx.json"
    snap = next((tmp_path / "snapshots").glob("*.json"))
    code, out = run(capsys, "export", str(snap), "--format", "spdx", "-o", str(target))
    assert code == 0 and out.out == ""
    assert json.loads(target.read_text())["spdxVersion"] == "SPDX-2.3"


def test_log(installed, tmp_path, capsys):
    run(capsys, "scan", "--state-dir", str(tmp_path))
    installed["pkgs"] = [Package("pip", "jinja2", "3.1", "/e")]
    run(capsys, "scan", "--state-dir", str(tmp_path))
    code, out = run(capsys, "log", "Jinja2", "--state-dir", str(tmp_path))
    assert code == 0
    assert [line.split("  ")[1] for line in out.out.splitlines()] == [
        "+ pip jinja2 2.10 (/e)",
        "^ pip jinja2 2.10 -> 3.1 (/e)",
    ]
    code, out = run(capsys, "log", "jinja2", "--json", "--state-dir", str(tmp_path))
    assert [e["kind"] for e in json.loads(out.out)] == ["added", "upgraded"]
    code, out = run(capsys, "log", "nope", "--state-dir", str(tmp_path))
    assert out.out.strip() == "nope: not in any scan"


@pytest.mark.usefixtures("osv")
def test_watch_saves_only_on_change(installed, tmp_path, capsys, monkeypatch):
    sleeps = []
    changes = iter([[], [Package("pip", "new", "2.10", "/e")], []])

    def sleep(seconds):
        sleeps.append(seconds)
        installed["pkgs"] = installed["pkgs"] + next(changes)

    monkeypatch.setattr(cli.time, "sleep", sleep)
    args = ("watch", "--state-dir", str(tmp_path), "--interval", "5", "--vulns")
    code, out = run(capsys, *args, "--count", "4")
    assert code == 0 and sleeps == [5, 5, 5]
    lines = out.out.splitlines()
    assert "first scan, 1 packages" in lines[0]
    assert lines[1].endswith("+ pip new 2.10 (/e)")
    assert "! pip new 2.10 (/e)" in lines[2]
    assert len(list((tmp_path / "snapshots").glob("*.json"))) == 2


def test_watch_json_and_osv_down(installed, tmp_path, capsys, monkeypatch):
    def down(*_args):
        raise OSError("offline")

    monkeypatch.setattr(vulns, "lookup", down)
    run(capsys, "watch", "--state-dir", str(tmp_path), "--json", "--count", "1")
    installed["pkgs"] = [Package("pip", "jinja2", "3.0", "/e")]
    code, out = run(
        capsys,
        "watch",
        "--state-dir",
        str(tmp_path),
        "--json",
        "--count",
        "1",
        "--vulns",
    )
    assert code == 0 and "offline" in out.err
    data = json.loads(out.out)
    assert data["upgraded"][0]["new"]["version"] == "3.0" and data["vulns"] == []


@pytest.mark.usefixtures("installed")
def test_watch_stops_on_ctrl_c(tmp_path, capsys, monkeypatch):
    def interrupt(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", interrupt)
    code, _ = run(capsys, "watch", "--state-dir", str(tmp_path))
    assert code == 0


def test_bad_numbers_are_usage_errors(capsys):
    for argv in (["watch", "--interval", "0"], ["prune", "--keep", "x"]):
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        assert exc.value.code == 2
    assert "not a positive number" in capsys.readouterr().err


@pytest.mark.usefixtures("installed")
def test_prune(tmp_path, capsys):
    for _ in range(3):
        run(capsys, "scan", "--state-dir", str(tmp_path))
    code, out = run(
        capsys, "prune", "--keep", "1", "--dry-run", "--state-dir", str(tmp_path)
    )
    assert code == 0 and out.out.splitlines()[-1] == "would delete 2 snapshots"
    assert len(list((tmp_path / "snapshots").glob("*.json"))) == 3
    code, out = run(capsys, "prune", "--keep", "1", "--state-dir", str(tmp_path))
    assert out.out.splitlines()[-1] == "deleted 2 snapshots"
    assert len(list((tmp_path / "snapshots").glob("*.json"))) == 1


def test_diff_skips_corrupt_newest_scan(installed, tmp_path, capsys):
    run(capsys, "scan", "--state-dir", str(tmp_path))
    installed["pkgs"] = []
    run(capsys, "scan", "--state-dir", str(tmp_path))
    (tmp_path / "snapshots" / "scan-99999999T999999Z.json").write_text("{")
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 3 and "- pip jinja2 2.10 (/e)" in out.out
    assert "skipping" in out.err


@pytest.mark.usefixtures("installed")
def test_new_collectors_are_not_run_in_old_scans(tmp_path, capsys):
    old = {
        "schema": 3,
        "collectors": {"pip": "ok"},
        "created": "2026-01-01T00:00:00Z",
        "host": "h",
        "packages": [
            {
                "ecosystem": "pip",
                "name": "jinja2",
                "version": "2.10",
                "location": "/e",
                "source": "",
            }
        ],
        "roots": None,
    }
    folder = tmp_path / "snapshots"
    folder.mkdir()
    (folder / "scan-20260101T000000Z.json").write_text(json.dumps(old))
    run(capsys, "scan", "--state-dir", str(tmp_path))
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 0
    assert out.out.splitlines() == [
        "no changes",
        "note: npm not compared (not run in OLD)",
    ]


@pytest.mark.usefixtures("installed")
def test_verbose_logs_to_stderr(tmp_path, capsys):
    code, _ = run(capsys, "scan", "-vv", "--no-save", "--state-dir", str(tmp_path))
    assert code == 0
