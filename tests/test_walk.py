import json
import os

import pytest

from bomwatch import walk
from bomwatch.collectors import npm_project
from bomwatch.model import Package


def project(path, deps):
    path.mkdir(parents=True)
    (path / "package.json").write_text("{}")
    for name, version in deps.items():
        dep = path / "node_modules" / name
        dep.mkdir(parents=True)
        (dep / "package.json").write_text(
            json.dumps({"name": name, "version": version})
        )
    return path


def test_find_projects_and_cache(tmp_path):
    app = project(tmp_path / "app", {"left-pad": "1.3.0"})
    project(tmp_path / "app" / "packages" / "ui", {"react": "18.0.0"})
    (tmp_path / "no-deps").mkdir()
    (tmp_path / "no-deps" / "package.json").write_text("{}")
    found = walk.find([tmp_path])
    assert found.projects == (app, app / "packages" / "ui")
    project(tmp_path / "later", {"x": "1.0.0"})
    assert walk.find([tmp_path]) is found
    walk.clear()
    assert len(walk.find([tmp_path]).projects) == 3


def test_npm_project_collect(tmp_path):
    app = project(tmp_path / "app", {"left-pad": "1.3.0", "@s/t": "2.0.0"})
    assert npm_project.collect([tmp_path]) == [
        Package("npm-project", "@s/t", "2.0.0", str(app / "node_modules"), "project"),
        Package(
            "npm-project", "left-pad", "1.3.0", str(app / "node_modules"), "project"
        ),
    ]


@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: 0)() == 0, reason="root reads any dir"
)
def test_unreadable_dirs_are_counted(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        assert walk.find([tmp_path]).unreadable == 1
    finally:
        locked.chmod(0o755)


def test_unreadable_via_onerror(tmp_path, monkeypatch):
    real_walk = os.walk

    def fake_walk(root, onerror=None):
        onerror(PermissionError(13, "Permission denied", str(tmp_path / "x")))
        yield from real_walk(root)

    monkeypatch.setattr(walk.os, "walk", fake_walk)
    assert walk.find([tmp_path]).unreadable == 1
