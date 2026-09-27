from datetime import datetime, timezone

from bomwatch import history, snapshot
from bomwatch.model import Package


def save(tmp_path, hour, packages, status, roots=None):
    now = datetime(2026, 9, 27, hour, tzinfo=timezone.utc)
    return snapshot.save(snapshot.make(packages, status, roots, now, "h", {}), tmp_path)


def test_events_track_one_package(tmp_path):
    ok = {"pip": "ok", "npm": "ok"}
    files = [
        save(tmp_path, 1, [Package("npm", "other", "1")], ok),
        save(tmp_path, 2, [Package("pip", "jinja2", "2.10", "/e")], ok),
        save(tmp_path, 3, [], {"pip": "failed"}),
        save(tmp_path, 4, [Package("pip", "jinja2", "3.1", "/e")], ok),
        save(tmp_path, 5, [Package("pip", "jinja2", "3.0", "/e")], ok),
        save(tmp_path, 6, [], ok),
    ]
    (tmp_path / "snapshots" / "scan-20260927T070000Z.json").write_text("junk")
    files = snapshot.history(tmp_path)
    found = history.events(files, "JINJA_2".replace("_", ""))
    assert [e["kind"] for e in found] == ["added", "upgraded", "downgraded", "removed"]
    lines = history.to_lines(found)
    assert lines[0] == "2026-09-27T02:00:00Z  + pip jinja2 2.10 (/e)"
    assert lines[1] == "2026-09-27T04:00:00Z  ^ pip jinja2 2.10 -> 3.1 (/e)"
    data = history.to_dict(found)
    assert data[1]["old_version"] == "2.10" and data[0]["old_version"] is None
    assert not history.events(files, "jinja2", ecosystem="npm")


def test_events_ignore_scans_of_other_roots(tmp_path):
    ok = {"pip": "ok"}
    save(tmp_path, 1, [Package("pip", "a", "1", "/home/e")], ok, ["/home"])
    save(tmp_path, 2, [], ok, ["/srv"])
    save(tmp_path, 3, [Package("pip", "a", "1", "/home/e")], ok, ["/home"])
    files = snapshot.history(tmp_path)
    assert [e["kind"] for e in history.events(files, "a", uses_roots=("pip",))] == [
        "added"
    ]
    assert len(history.events(files, "a")) == 3
