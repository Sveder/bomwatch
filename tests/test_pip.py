import json
import os
import sys

import pytest

from bomwatch import diff
from bomwatch.collectors import pip
from bomwatch.model import Package
from bomwatch.runner import run


def make_env(path):
    (path / "bin").mkdir(parents=True)
    (path / "pyvenv.cfg").write_text("home = /usr/bin\n")
    return path


def add_dist(prefix, name, version, kind="dist-info", python="python3.12"):
    site = prefix / "lib" / python / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    text = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nBody\n"
    if kind == "dist-info":
        folder = site / f"{name}-{version}.dist-info"
        folder.mkdir()
        (folder / "METADATA").write_text(text)
    elif kind == "egg-dir":
        folder = site / f"{name}-{version}.egg-info"
        folder.mkdir()
        (folder / "PKG-INFO").write_text(text)
    else:
        (site / f"{name}-{version}.egg-info").write_text(text)
    return site


@pytest.fixture(name="no_system")
def fixture_no_system(monkeypatch, tmp_path):
    monkeypatch.setattr(pip, "SYSTEM_PYTHON", str(tmp_path / "missing-python"))
    monkeypatch.setattr(pip.Path, "home", lambda: tmp_path / "home")


def test_normalize():
    assert pip.normalize("Typing_Extensions") == "typing-extensions"
    assert pip.normalize("zope.interface") == "zope-interface"
    assert pip.normalize("a--b__c") == "a-b-c"


def test_find_envs_skips_nested_and_ignored_dirs(tmp_path):
    env = make_env(tmp_path / "proj" / ".venv")
    make_env(tmp_path / "proj" / ".venv" / "inner")
    make_env(tmp_path / "node_modules" / "env")
    assert pip.find_envs([tmp_path]) == [env]


def test_find_envs_respects_depth(tmp_path):
    make_env(tmp_path / "a" / "b" / "c")
    assert not pip.find_envs([tmp_path], max_depth=1)


def test_find_envs_conda_base_and_envs(tmp_path):
    base = tmp_path / "miniconda3"
    (base / "conda-meta").mkdir(parents=True)
    (base / "pkgs" / "x" / "conda-meta").mkdir(parents=True)
    (base / "envs" / "ml" / "conda-meta").mkdir(parents=True)
    assert pip.find_envs([tmp_path]) == [base, base / "envs" / "ml"]


def test_read_site_formats_and_junk(tmp_path):
    add_dist(tmp_path, "Rich", "13.0")
    add_dist(tmp_path, "old_egg", "0.1", kind="egg-dir")
    site = add_dist(tmp_path, "flat.egg", "2", kind="egg-file")
    (site / "noname.dist-info").mkdir()
    (site / "noname.dist-info" / "METADATA").write_text("Version: 1\n")
    (site / "nometa.dist-info").mkdir()
    (site / "module.py").write_text("")
    assert sorted(pip.read_site(site, "/env", "venv")) == [
        Package("pip", "flat-egg", "2", "/env", "venv"),
        Package("pip", "old-egg", "0.1", "/env", "venv"),
        Package("pip", "rich", "13.0", "/env", "venv"),
    ]


def test_site_dirs_only_python3(tmp_path):
    add_dist(tmp_path, "a", "1")
    (tmp_path / "lib" / "node").mkdir()
    assert pip.site_dirs(tmp_path) == [
        tmp_path / "lib" / "python3.12" / "site-packages"
    ]
    assert not pip.site_dirs(tmp_path / "missing")


@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: 0)() == 0, reason="root reads any dir"
)
def test_unreadable_site_packages_is_empty(tmp_path):
    site = add_dist(tmp_path, "a", "1")
    site.chmod(0)
    try:
        assert not pip.read_prefix(tmp_path, "/env", "venv")
    finally:
        site.chmod(0o755)


def test_parse_normalizes_and_skips_empty_names():
    output = json.dumps([["Typing_Extensions", "4.0"], ["", "1"]])
    assert pip.parse(output) == [
        Package("pip", "typing-extensions", "4.0", "system", "system")
    ]


def test_parse_bad_output_is_a_failure():
    assert pip.parse("not json") is None
    assert pip.parse(None) is None
    assert pip.parse('{"a": 1}') is None


def test_windows_env_layout(tmp_path):
    site = tmp_path / "Lib" / "site-packages"
    (site / "rich-13.0.dist-info").mkdir(parents=True)
    (site / "rich-13.0.dist-info" / "METADATA").write_text(
        "Name: rich\nVersion: 13.0\n"
    )
    assert pip.site_dirs(tmp_path) == [site]
    assert pip.read_prefix(tmp_path, "C:/env", "venv") == [
        Package("pip", "rich", "13.0", "C:/env", "venv")
    ]


def test_windows_user_sites(tmp_path, monkeypatch):
    site = tmp_path / "Python" / "Python312" / "site-packages"
    (site / "six-1.0.dist-info").mkdir(parents=True)
    (site / "six-1.0.dist-info" / "METADATA").write_text("Name: six\nVersion: 1.0\n")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setattr(pip.sys, "platform", "win32")
    assert pip.windows_user_sites() == [
        Package("pip", "six", "1.0", "user-site/python312", "user")
    ]
    monkeypatch.setattr(pip.sys, "platform", "linux")
    assert not pip.windows_user_sites()


def test_system_packages_uses_fixed_path(monkeypatch, tmp_path):
    python = tmp_path / "python3"
    python.write_text("")
    calls = []
    monkeypatch.setattr(pip, "SYSTEM_PYTHON", str(python))
    monkeypatch.setattr(
        pip, "run", lambda cmd: calls.append(cmd) or json.dumps([["six", "1.16"]])
    )
    assert pip.system_packages() == [Package("pip", "six", "1.16", "system", "system")]
    assert calls[0][0] == str(python)


def test_system_python_failing_is_none(monkeypatch, tmp_path):
    (tmp_path / "python3").write_text("")
    monkeypatch.setattr(pip, "SYSTEM_PYTHON", str(tmp_path / "python3"))
    monkeypatch.setattr(pip, "run", lambda cmd: None)
    assert pip.system_packages() is None
    assert pip.collect([]) is None


@pytest.mark.usefixtures("no_system")
def test_collect_user_site_venvs_and_conda(tmp_path):
    add_dist(tmp_path / "home" / ".local", "adbutils", "2.0")
    env = make_env(tmp_path / "proj" / ".venv")
    add_dist(env, "requests", "2.31")
    conda = tmp_path / "conda"
    (conda / "conda-meta").mkdir(parents=True)
    add_dist(conda, "numpy", "2.0")
    assert sorted(pip.collect([tmp_path / "proj", tmp_path / "conda"])) == [
        Package("pip", "adbutils", "2.0", "user-site/python3.12", "user"),
        Package("pip", "numpy", "2.0", str(conda), "conda"),
        Package("pip", "requests", "2.31", str(env), "venv"),
    ]


@pytest.mark.usefixtures("no_system")
def test_broken_python_symlink_still_listed(tmp_path):
    env = make_env(tmp_path / "env")
    (env / "bin" / "python").symlink_to(tmp_path / "gone" / "python3.11")
    add_dist(env, "six", "1.16")
    assert pip.collect([tmp_path]) == [Package("pip", "six", "1.16", str(env), "venv")]


@pytest.mark.usefixtures("no_system")
def test_env_python_is_never_run(tmp_path):
    env = make_env(tmp_path / "env")
    marker = tmp_path / "ran"
    python = env / "bin" / "python"
    python.write_text(f"#!/bin/sh\ntouch {marker}\n")
    python.chmod(0o755)
    add_dist(env, "six", "1.16")
    assert len(pip.collect([tmp_path])) == 1
    assert not marker.exists()


def test_list_script_runs_in_real_python():
    output = run([sys.executable, "-I", "-c", pip.LIST_SCRIPT])
    assert "pytest" in {pkg.name for pkg in pip.parse(output)}


@pytest.mark.usefixtures("no_system")
def test_two_python_versions_give_unique_keys(tmp_path):
    user = tmp_path / "home" / ".local"
    add_dist(user, "foo", "1.0", python="python3.10")
    add_dist(user, "foo", "2.0")
    env = make_env(tmp_path / "env")
    add_dist(env, "bar", "1.0", python="python3.11")
    add_dist(env, "bar", "1.0")
    packages = pip.collect([tmp_path / "env"])
    assert len({pkg.key for pkg in packages}) == len(packages) == 4
    assert {pkg.location for pkg in packages} == {
        "user-site/python3.10",
        "user-site/python3.12",
        f"{env}/python3.11",
        f"{env}/python3.12",
    }


def test_single_site_env_keeps_plain_location(tmp_path):
    add_dist(tmp_path, "six", "1.16")
    assert pip.read_prefix(tmp_path, "/env", "venv")[0].location == "/env"


@pytest.mark.usefixtures("no_system")
def test_removing_one_python_copy_is_reported(tmp_path):
    user = tmp_path / "home" / ".local"
    add_dist(user, "foo", "1.0", python="python3.10")
    add_dist(user, "foo", "2.0")
    old = pip.collect([])
    for path in (user / "lib" / "python3.10").rglob("*"):
        if path.is_file():
            path.unlink()
    changes = diff.compare(old, pip.collect([]))
    assert [pkg.location for pkg in changes["removed"]] == ["user-site/python3.10"]
