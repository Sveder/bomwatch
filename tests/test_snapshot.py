import json
from datetime import datetime, timezone
from pathlib import Path


import pytest

from bomwatch import snapshot
from bomwatch.model import Package

NOW = datetime(2026, 9, 27, 1, 2, 3, tzinfo=timezone.utc)
PKGS = [Package("pip", "b", "2"), Package("dpkg", "a", "1", "/", "apt")]


def test_state_dir_order(monkeypatch, tmp_path):
    monkeypatch.setenv("BOMWATCH_STATE_DIR", str(tmp_path / "env"))
    assert snapshot.state_dir(tmp_path / "flag") == tmp_path / "flag"
    assert snapshot.state_dir() == tmp_path / "env"
    monkeypatch.delenv("BOMWATCH_STATE_DIR")
    assert snapshot.state_dir() == Path.home() / ".local/state/bomwatch"


def test_make_is_sorted():
    snap = snapshot.make(PKGS, {"pip": "ok", "dpkg": "ok"}, now=NOW, host="h")
    assert snap["collectors"] == {"dpkg": "ok", "pip": "ok"}
    assert snap["created"] == "2026-09-27T01:02:03Z"
    assert snap["host"] == "h"
    assert snap["schema"] == 3
    assert snap["roots"] is None
    assert [p["name"] for p in snap["packages"]] == ["a", "b"]


def test_make_defaults():
    snap = snapshot.make([])
    assert snap["host"] and snap["created"].endswith("Z")


def test_save_load_roundtrip(tmp_path):
    path = snapshot.save(snapshot.make(PKGS, now=NOW, host="h"), tmp_path)
    assert path == tmp_path / "snapshots" / "scan-20260927T010203Z.json"
    assert json.loads(path.read_text())["host"] == "h"
    assert snapshot.load(path)["packages"] == sorted(PKGS)
    assert snapshot.history(tmp_path) == [path]


def test_load_schema_1_has_empty_status(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"schema": 1, "packages": [PKGS[0].to_dict()]}))
    assert snapshot.load(path)["collectors"] == {}


def test_history_empty(tmp_path):
    assert not snapshot.history(tmp_path)


def test_same_second_does_not_overwrite(tmp_path):
    snap = snapshot.make(PKGS, now=NOW, host="h")
    paths = [snapshot.save(snap, tmp_path) for _ in range(3)]
    assert [p.name for p in paths] == [
        "scan-20260927T010203Z.json",
        "scan-20260927T010203Z-1.json",
        "scan-20260927T010203Z-2.json",
    ]
    assert snapshot.history(tmp_path) == paths


def test_history_counts_same_second_files_as_numbers(tmp_path):
    snap = snapshot.make(PKGS, now=NOW, host="h")
    paths = [snapshot.save(snap, tmp_path) for _ in range(12)]
    assert snapshot.history(tmp_path) == paths


def save_scan(tmp_path, packages, status):
    return snapshot.save(snapshot.make(packages, status, host="h"), tmp_path)


def test_baseline_takes_newest_ok_per_collector(tmp_path):
    old_pip = Package("pip", "b", "1")
    files = [
        save_scan(tmp_path, [PKGS[1], old_pip], {"dpkg": "ok", "pip": "ok"}),
        save_scan(tmp_path, [PKGS[0]], {"dpkg": "failed", "pip": "ok"}),
    ]
    base = snapshot.baseline(files, ["dpkg", "pip"])
    assert base["collectors"] == {"dpkg": "ok", "pip": "ok"}
    assert sorted(base["packages"]) == sorted(PKGS)


def test_baseline_keeps_status_when_never_ok(tmp_path):
    files = [save_scan(tmp_path, [], {"dpkg": "ok", "npm": "failed"})]
    base = snapshot.baseline(files, ["npm"])
    assert base == {
        "collectors": {"dpkg": "ok", "npm": "failed"},
        "packages": [],
        "roots": None,
    }


def test_make_records_roots():
    snap = snapshot.make([], roots=[Path("/b"), Path("/a")])
    assert snap["roots"] == ["/a", "/b"]


def test_baseline_takes_only_same_roots(tmp_path):
    same = snapshot.make([PKGS[0]], {"pip": "ok"}, roots=["/home"], host="h")
    other = snapshot.make([], {"pip": "ok"}, roots=["/srv"], host="h")
    unknown = snapshot.make([], {"pip": "ok"}, host="h")
    files = [snapshot.save(s, tmp_path) for s in (same, other)]
    base = snapshot.baseline(files, ["pip"], ["/home"], ("pip",))
    assert base["packages"] == [PKGS[0]] and base["roots"] == ["/home"]
    base = snapshot.baseline(files[1:], ["pip"], ["/home"], ("pip",))
    assert base["collectors"] == {"pip": "other roots"}
    files.append(snapshot.save(unknown, tmp_path))
    assert snapshot.baseline(files, ["pip"], ["/srv"], ("pip",))["packages"] == []


@pytest.mark.parametrize(
    "text",
    ["not json", "[1]", '{"schema": 3}', '{"packages": [1]}', '{"packages": [{}]}'],
)
def test_load_rejects_other_files(tmp_path, text):
    path = tmp_path / "x.json"
    path.write_text(text)
    with pytest.raises(ValueError, match="not a bomwatch snapshot"):
        snapshot.load(path)
