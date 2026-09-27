import json
import subprocess
import sys

import pytest

from bomwatch import cli, collectors
from bomwatch.model import Package


@pytest.fixture(name="installed")
def fixture_installed(monkeypatch):
    state = {
        "pkgs": [Package("pip", "a", "1", "/e"), Package("dpkg", "b", "1")],
        "failed": set(),
    }

    def status(name, only):
        if only and name not in only:
            return "skipped"
        return "failed" if name in state["failed"] else "ok"

    def fake_collect_all(_roots=None, only=None):
        found = {n: status(n, only) for n in ("dpkg", "npm", "pip")}
        return [p for p in state["pkgs"] if found[p.ecosystem] == "ok"], found

    monkeypatch.setattr(collectors, "collect_all", fake_collect_all)
    return state


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, capsys.readouterr()


def scan(tmp_path, capsys, *extra):
    return run(capsys, "scan", "--state-dir", str(tmp_path), *extra)


@pytest.mark.usefixtures("installed")
def test_scan_prints_counts_and_saves(tmp_path, capsys):
    code, out = scan(tmp_path, capsys)
    assert code == 0
    assert "dpkg         1" in out.out and "total        2" in out.out
    assert len(list((tmp_path / "snapshots").glob("scan-*.json"))) == 1


@pytest.mark.usefixtures("installed")
def test_scan_json_no_save(tmp_path, capsys):
    code, out = scan(tmp_path, capsys, "--no-save", "--json", "--only", "pip")
    assert code == 0
    assert json.loads(out.out) == {
        "snapshot": None,
        "counts": {"pip": 1},
        "collectors": {"dpkg": "skipped", "npm": "skipped", "pip": "ok"},
    }
    assert not (tmp_path / "snapshots").exists()


@pytest.mark.usefixtures("installed")
def test_scan_text_no_save_prints_no_path(tmp_path, capsys):
    code, out = scan(tmp_path, capsys, "--no-save")
    assert code == 0
    assert "total        2" in out.out and "saved" not in out.out


def test_scan_unknown_collector(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        scan(tmp_path, capsys, "--only", "dpkg,nope,zz")
    assert exc.value.code == 2
    assert "unknown collector: nope, zz" in capsys.readouterr().err


def scan_twice(installed, tmp_path, monkeypatch, capsys):
    stamps = iter(["2026-09-27T01:00:00Z", "2026-09-27T02:00:00Z"])
    real_make = cli.snapshot.make

    def make(packages, status, **kwargs):
        snap = real_make(packages, status, **kwargs)
        snap["created"] = next(stamps)
        return snap

    monkeypatch.setattr(cli.snapshot, "make", make)
    scan(tmp_path, capsys)
    installed["pkgs"] = [Package("pip", "a", "2", "/e"), Package("npm", "c", "1")]
    scan(tmp_path, capsys)


@pytest.mark.usefixtures("installed")
def test_diff_first_scan(tmp_path, capsys):
    scan(tmp_path, capsys)
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 0
    assert out.out.strip() == "first scan, nothing to compare"


@pytest.mark.usefixtures("installed")
def test_diff_first_scan_json(tmp_path, capsys):
    scan(tmp_path, capsys)
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path), "--json")
    assert code == 0
    assert json.loads(out.out) == {
        "first_scan": True,
        "added": [],
        "removed": [],
        "upgraded": [],
        "downgraded": [],
        "changed": [],
        "not_compared": {},
    }


def test_diff_bad_snapshot_is_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema": 3}')
    code, out = run(capsys, "diff", str(bad), str(bad))
    assert code == 1
    assert out.err.strip() == f"bomwatch: not a bomwatch snapshot: {bad}"


def test_diff_latest_two(installed, tmp_path, monkeypatch, capsys):
    scan_twice(installed, tmp_path, monkeypatch, capsys)
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 3
    assert out.out.splitlines() == [
        "+ npm c 1 ()",
        "- dpkg b 1 ()",
        "^ pip a 1 -> 2 (/e)",
    ]


def test_diff_files_json_and_no_change(installed, tmp_path, monkeypatch, capsys):
    scan_twice(installed, tmp_path, monkeypatch, capsys)
    old, new = sorted((tmp_path / "snapshots").glob("*.json"))
    code, out = run(capsys, "diff", str(old), str(new), "--json")
    assert code == 3
    data = json.loads(out.out)
    assert data["upgraded"][0]["old"]["version"] == "1"
    assert data["not_compared"] == {}
    code, out = run(capsys, "diff", str(new), str(new))
    assert code == 0
    assert out.out.strip() == "no changes"


def test_partial_scan_reports_no_removals(installed, tmp_path, capsys):
    installed["pkgs"].append(Package("npm", "c", "1"))
    scan(tmp_path, capsys)
    scan(tmp_path, capsys, "--only", "dpkg,pip")
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 0
    assert out.out.splitlines() == [
        "no changes",
        "note: npm not compared (skipped in NEW)",
    ]


def test_failed_collector_reports_no_removals(installed, tmp_path, capsys):
    scan(tmp_path, capsys)
    installed["failed"] = {"dpkg"}
    scan(tmp_path, capsys)
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path), "--json")
    assert code == 0
    data = json.loads(out.out)
    assert data["removed"] == []
    assert data["not_compared"] == {"dpkg": "failed in NEW"}


def test_change_during_skipped_scan_is_reported(installed, tmp_path, capsys):
    scan(tmp_path, capsys, "--only", "dpkg,pip")
    scan(tmp_path, capsys)
    installed["pkgs"].append(Package("npm", "c", "1"))
    scan(tmp_path, capsys, "--only", "dpkg")
    scan(tmp_path, capsys)
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 3
    assert out.out.splitlines() == ["+ npm c 1 ()"]


def test_change_during_failed_scan_is_reported(installed, tmp_path, capsys):
    scan(tmp_path, capsys)
    installed["failed"] = {"npm"}
    scan(tmp_path, capsys)
    installed["failed"] = set()
    installed["pkgs"].append(Package("npm", "c", "1"))
    scan(tmp_path, capsys)
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 3
    assert out.out.splitlines() == ["+ npm c 1 ()"]


def test_never_ok_collector_is_not_compared(installed, tmp_path, capsys):
    scan(tmp_path, capsys, "--only", "dpkg")
    installed["pkgs"].append(Package("npm", "c", "1"))
    scan(tmp_path, capsys)
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 0
    assert out.out.splitlines() == [
        "no changes",
        "note: npm not compared (skipped in OLD)",
        "note: pip not compared (skipped in OLD)",
    ]


def test_explicit_files_compare_only_the_pair(installed, tmp_path, capsys):
    scan(tmp_path, capsys)
    installed["pkgs"].append(Package("npm", "c", "1"))
    scan(tmp_path, capsys, "--only", "dpkg")
    scan(tmp_path, capsys)
    _, middle, last = (str(p) for p in cli.snapshot.history(tmp_path))
    code, out = run(capsys, "diff", middle, last)
    assert code == 0
    assert "note: npm not compared (skipped in OLD)" in out.out


def test_scan_warns_on_failed_collector(installed, tmp_path, capsys):
    installed["failed"] = {"dpkg"}
    code, out = scan(tmp_path, capsys)
    assert code == 0
    assert "collector failed: dpkg" in out.err


def test_diff_one_file_is_usage_error(capsys):
    code, _ = run(capsys, "diff", "only-one.json")
    assert code == 2


def test_diff_missing_file_is_error(tmp_path, capsys):
    code, out = run(capsys, "diff", str(tmp_path / "a"), str(tmp_path / "b"))
    assert code == 1
    assert out.err.startswith("bomwatch:")


def write_snapshot(path, count, version):
    pkgs = [Package("pip", f"p{i}", version, "/e") for i in range(count)]
    path.write_text(json.dumps(cli.snapshot.make(pkgs, {})), encoding="utf-8")
    return str(path)


def test_diff_into_closed_pipe_is_quiet(tmp_path):
    old = write_snapshot(tmp_path / "old.json", 20000, "1")
    new = write_snapshot(tmp_path / "new.json", 20000, "2")
    with subprocess.Popen(
        [sys.executable, "-m", "bomwatch", "diff", old, new],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        proc.stdout.readline()
        proc.stdout.close()
        stderr = proc.stderr.read()
        proc.wait()
    assert b"Traceback" not in stderr
    assert proc.returncode == 0


def test_broken_pipe_returns_ok(monkeypatch):
    def broken(_args):
        raise BrokenPipeError

    calls = []
    monkeypatch.setattr(cli, "cmd_diff", broken)
    monkeypatch.setattr(cli.os, "dup2", lambda *a: calls.append(a))
    monkeypatch.setattr(cli.sys, "stdout", type("Out", (), {"fileno": lambda s: 1})())
    assert cli.main(["diff"]) == 0
    assert calls


def test_other_roots_make_no_false_removals(installed, tmp_path, capsys):
    scan(tmp_path, capsys)
    installed["pkgs"] = [Package("dpkg", "b", "1")]
    scan(tmp_path, capsys, "--root", "/srv")
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 0
    assert out.out.splitlines() == [
        "no changes",
        "note: pip not compared (other roots in OLD)",
    ]
    old, new = (str(p) for p in cli.snapshot.history(tmp_path))
    code, out = run(capsys, "diff", old, new, "--json")
    assert code == 0
    assert json.loads(out.out)["not_compared"] == {"pip": "roots differ"}


def test_diff_skips_scan_with_other_roots(installed, tmp_path, capsys):
    scan(tmp_path, capsys)
    pkgs = installed["pkgs"]
    installed["pkgs"] = [Package("dpkg", "b", "1")]
    scan(tmp_path, capsys, "--root", "/srv")
    installed["pkgs"] = pkgs + [Package("pip", "new", "1", "/e")]
    scan(tmp_path, capsys)
    code, out = run(capsys, "diff", "--state-dir", str(tmp_path))
    assert code == 3
    assert out.out.splitlines() == ["+ pip new 1 (/e)"]


def test_scan_saves_absolute_roots(installed, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scan(tmp_path, capsys, "--root", "b", "--root", "a", "--root", "a")
    (path,) = cli.snapshot.history(tmp_path)
    assert installed and cli.snapshot.load(path)["roots"] == [
        str(tmp_path / "a"),
        str(tmp_path / "b"),
    ]
