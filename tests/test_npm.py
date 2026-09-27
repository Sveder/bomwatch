import json
import os

import pytest

from bomwatch.collectors import npm
from bomwatch.model import Package


def add_package(node_modules, name, version="1.0.0", body=None):
    path = node_modules / name
    path.mkdir(parents=True)
    data = body if body is not None else {"name": name, "version": version}
    (path / "package.json").write_text(json.dumps(data))


def test_scan_node_modules(tmp_path):
    nm = tmp_path / "node_modules"
    add_package(nm, "left-pad", "1.3.0")
    add_package(nm, "@scope/tool", "2.0.0")
    add_package(nm, "broken", body=[])
    (nm / ".bin").mkdir()
    (nm / "no-json").mkdir()
    (nm / "README").write_text("")
    assert npm.scan_node_modules(nm, "npm-global") == [
        Package("npm", "@scope/tool", "2.0.0", str(nm), "npm-global"),
        Package("npm", "left-pad", "1.3.0", str(nm), "npm-global"),
    ]


def test_scan_missing_dir(tmp_path):
    assert not npm.scan_node_modules(tmp_path / "nope", "npm-global")


def test_global_roots_finds_nvm_and_npm_root(tmp_path, monkeypatch):
    nvm = tmp_path / ".nvm/versions/node/v22.0.0/lib/node_modules"
    nvm.mkdir(parents=True)
    monkeypatch.setattr(npm, "has", lambda tool: True)
    monkeypatch.setattr(npm, "run", lambda cmd: "/usr/lib/node_modules\n")
    assert npm.global_roots(tmp_path) == sorted(
        [nvm, npm.Path("/usr/lib/node_modules")]
    )


def test_collect(tmp_path, monkeypatch):
    nvm = tmp_path / ".nvm/versions/node/v22.0.0/lib/node_modules"
    add_package(nvm, "npm", "10.0.0")
    monkeypatch.setattr(npm, "has", lambda tool: False)
    assert npm.collect([], home=tmp_path) == [
        Package("npm", "npm", "10.0.0", str(nvm), "npm-global")
    ]


def test_collect_failing_npm_is_none(tmp_path, monkeypatch):
    monkeypatch.setattr(npm, "has", lambda tool: True)
    monkeypatch.setattr(npm, "run", lambda cmd: None)
    assert npm.collect([], home=tmp_path) is None


def test_global_roots_ignores_empty_npm_output(tmp_path, monkeypatch):
    monkeypatch.setattr(npm, "has", lambda tool: True)
    monkeypatch.setattr(npm, "run", lambda cmd: "\n")
    assert not npm.global_roots(tmp_path)


@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: 0)() == 0, reason="root can read a mode 000 dir"
)
def test_unreadable_scope_dir_is_skipped(tmp_path):
    nm = tmp_path / "node_modules"
    add_package(nm, "left-pad", "1.3.0")
    add_package(nm, "@evil/pkg")
    (nm / "@evil").chmod(0)
    try:
        assert npm.scan_node_modules(nm, "npm-global") == [
            Package("npm", "left-pad", "1.3.0", str(nm), "npm-global")
        ]
    finally:
        (nm / "@evil").chmod(0o755)


def test_list_dir_missing(tmp_path):
    assert not npm.list_dir(tmp_path / "nope")
