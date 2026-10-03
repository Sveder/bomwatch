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
    assert snap["schema"] == 5
    assert snap["os"]["system"]
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
    assert base["collectors"] == {"dpkg": "ok", "npm": "failed"}
    assert base["packages"] == [] and base["roots"] is None


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


def test_save_leaves_no_temp_files(tmp_path):
    snapshot.save(snapshot.make(PKGS, now=NOW, host="h"), tmp_path)
    assert [p.name for p in (tmp_path / "snapshots").iterdir()] == [
        "scan-20260927T010203Z.json"
    ]


def test_save_without_hard_links(tmp_path, monkeypatch):
    def no_link(*_args):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(snapshot.os, "link", no_link)
    snap = snapshot.make(PKGS, now=NOW, host="h")
    paths = [snapshot.save(snap, tmp_path) for _ in range(2)]
    assert [p.name for p in paths] == [
        "scan-20260927T010203Z.json",
        "scan-20260927T010203Z-1.json",
    ]
    assert snapshot.load(paths[1])["host"] == "h"
    assert len(list((tmp_path / "snapshots").iterdir())) == 2


def test_save_on_windows_uses_rename(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "IS_WINDOWS", True)
    snap = snapshot.make(PKGS, now=NOW, host="h")
    real_rename = snapshot.os.rename

    def rename(src, dst):
        if Path(dst).exists():
            raise FileExistsError(dst)
        real_rename(src, dst)

    monkeypatch.setattr(snapshot.os, "rename", rename)
    paths = [snapshot.save(snap, tmp_path) for _ in range(2)]
    assert paths[1].name == "scan-20260927T010203Z-1.json"


def test_save_other_link_error_is_raised(tmp_path, monkeypatch):
    def broken(*_args):
        raise OSError(5, "I/O error")

    monkeypatch.setattr(snapshot.os, "link", broken)
    with pytest.raises(OSError):
        snapshot.save(snapshot.make(PKGS, now=NOW, host="h"), tmp_path)
    assert not list((tmp_path / "snapshots").iterdir())


def test_place_fallback_when_name_taken(tmp_path, monkeypatch):
    monkeypatch.setattr(
        snapshot.os, "link", lambda *a: (_ for _ in ()).throw(PermissionError(1, "x"))
    )
    tmp = tmp_path / "tmp"
    tmp.write_text("x")
    taken = tmp_path / "taken"
    taken.write_text("y")
    assert not snapshot._place(tmp, taken)  # pylint: disable=protected-access


def test_load_rejects_newer_schema(tmp_path):
    path = tmp_path / "new.json"
    path.write_text(json.dumps({"schema": 99, "packages": []}))
    with pytest.raises(ValueError, match="upgrade bomwatch"):
        snapshot.load(path)


def test_try_load_and_latest_skip_broken(tmp_path, capsys):
    good = snapshot.save(snapshot.make(PKGS, now=NOW, host="h"), tmp_path)
    broken = tmp_path / "snapshots" / "scan-20260927T020000Z.json"
    broken.write_text('{"packages": [')
    assert snapshot.try_load(broken) is None
    assert "skipping" in capsys.readouterr().err
    index, snap = snapshot.latest(snapshot.history(tmp_path))
    assert index == 0 and snap["host"] == "h"
    assert snapshot.latest([broken]) is None
    assert snapshot.baseline([broken], ["pip"]) is None
    assert snapshot.baseline([good, broken], ["pip"])["collectors"] == {
        "pip": "not run"
    }


def test_status_by_schema():
    assert snapshot.status({"schema": 1, "collectors": {}}, "npm") == "ok"
    assert snapshot.status({"schema": 3, "collectors": {}}, "npm") == "not run"
    assert (
        snapshot.status({"schema": 3, "collectors": {"npm": "failed"}}, "npm")
        == "failed"
    )


def test_prune(tmp_path):
    for hour in range(1, 5):
        now = datetime(2026, 9, 27, hour, tzinfo=timezone.utc)
        snapshot.save(snapshot.make([], now=now, host="h"), tmp_path)
    doomed = snapshot.prune(tmp_path, 3)
    assert [p.name for p in doomed] == ["scan-20260927T010000Z.json"]
    assert len(snapshot.history(tmp_path)) == 3
    assert not snapshot.prune(tmp_path, 10)


def test_state_dir_windows(monkeypatch, tmp_path):
    monkeypatch.delenv("BOMWATCH_STATE_DIR", raising=False)
    monkeypatch.setattr(snapshot.sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert snapshot.state_dir() == tmp_path / "bomwatch"


def test_os_info(monkeypatch):
    monkeypatch.setattr(
        snapshot.platform,
        "freedesktop_os_release",
        lambda: {"ID": "debian", "VERSION_ID": "12", "NAME": "Debian"},
    )
    info = snapshot.os_info()
    assert info["id"] == "debian" and info["version_id"] == "12" and "name" not in info

    def missing():
        raise OSError("no os-release")

    monkeypatch.setattr(snapshot.platform, "freedesktop_os_release", missing)
    assert "id" not in snapshot.os_info()
