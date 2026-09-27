import json

from bomwatch.collectors import userland
from bomwatch.model import Package


def test_brew_cellar_and_caskroom(tmp_path, monkeypatch):
    monkeypatch.setattr(userland, "BREW_PREFIXES", ())
    monkeypatch.delenv("HOMEBREW_PREFIX", raising=False)
    prefix = tmp_path / ".linuxbrew"
    for version in ("1.9", "1.10"):
        (prefix / "Cellar" / "jq" / version).mkdir(parents=True)
    (prefix / "Cellar" / "empty").mkdir()
    (prefix / "Caskroom" / "godot" / "4.3").mkdir(parents=True)
    assert userland.collect_brew([], home=tmp_path) == [
        Package("brew", "jq", "1.10", str(prefix), "formula"),
        Package("brew", "godot", "4.3", str(prefix), "cask"),
    ]
    monkeypatch.setenv("HOMEBREW_PREFIX", str(prefix))
    assert userland.brew_prefixes(tmp_path / "nohome") == [prefix]


def test_cargo_crates2_and_toml(tmp_path, monkeypatch):
    monkeypatch.delenv("CARGO_HOME", raising=False)
    base = tmp_path / ".cargo"
    base.mkdir()
    assert not userland.collect_cargo([], home=tmp_path)
    (base / ".crates.toml").write_text(
        '[v1]\n"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)"'
        ' = ["rg"]\n'
    )
    assert userland.collect_cargo([], home=tmp_path) == [
        Package("cargo", "ripgrep", "14.1.0", str(base), "registry")
    ]
    installs = {"installs": {"bat 0.24.0 (git+https://x)": {}, "junk": {}}}
    (base / ".crates2.json").write_text(json.dumps(installs))
    monkeypatch.setenv("CARGO_HOME", str(base))
    assert userland.collect_cargo([]) == [
        Package("cargo", "bat", "0.24.0", str(base), "git")
    ]


GO_OUTPUT = """/home/u/go/bin/gopls: go1.22.1
\tpath\tgolang.org/x/tools/gopls
\tmod\tgolang.org/x/tools/gopls\tv0.15.2\th1:abc=
\tdep\tgolang.org/x/mod\tv0.16.0\th1:def=
/home/u/go/bin/local: go1.22.1
\tpath\texample.com/local
\tmod\texample.com/local\t(devel)\t
/home/u/go/bin/std: go1.22.1
\tpath\tcmd/std
/home/u/go/bin/nopath: go1.22.1
"""


def test_parse_go():
    assert userland.parse_go(GO_OUTPUT) == [
        Package(
            "go",
            "golang.org/x/tools/gopls",
            "v0.15.2",
            "/home/u/go/bin/gopls",
            "golang.org/x/tools/gopls",
        ),
        Package(
            "go",
            "example.com/local",
            "go1.22.1",
            "/home/u/go/bin/local",
            "example.com/local",
        ),
        Package("go", "cmd/std", "go1.22.1", "/home/u/go/bin/std", "go"),
    ]


def test_collect_go(tmp_path, monkeypatch):
    monkeypatch.delenv("GOBIN", raising=False)
    monkeypatch.setenv("GOPATH", str(tmp_path / "gp"))
    assert userland.collect_go([], home=tmp_path) == []
    (tmp_path / "go" / "bin").mkdir(parents=True)
    (tmp_path / "gp" / "bin").mkdir(parents=True)
    monkeypatch.setenv("GOBIN", str(tmp_path / "go" / "bin"))
    monkeypatch.setattr(userland, "has", lambda tool: True)
    monkeypatch.setattr(userland, "run", lambda cmd: GO_OUTPUT)
    assert len(userland.collect_go([], home=tmp_path)) == 6
    monkeypatch.setattr(userland, "run", lambda cmd: None)
    assert userland.collect_go([], home=tmp_path) is None
    monkeypatch.setattr(userland, "has", lambda tool: False)
    assert userland.collect_go([], home=tmp_path) == []


def test_vscode_extensions_json_and_dirs(tmp_path):
    code = tmp_path / ".vscode" / "extensions"
    code.mkdir(parents=True)
    listing = [
        {"identifier": {"id": "MS-Python.python"}, "version": "2024.1.0"},
        {"broken": True},
    ]
    (code / "extensions.json").write_text(json.dumps(listing))
    cursor = tmp_path / ".cursor" / "extensions"
    for version in ("1.2.0", "1.10.0"):
        ext = cursor / f"esbenp.prettier-vscode-{version}"
        ext.mkdir(parents=True)
        (ext / "package.json").write_text(
            json.dumps(
                {"name": "prettier-vscode", "publisher": "esbenp", "version": version}
            )
        )
    (cursor / "junk").mkdir()
    (cursor / "file.txt").write_text("")
    assert userland.collect_vscode([], home=tmp_path) == [
        Package("vscode", "ms-python.python", "2024.1.0", str(code), "editor"),
        Package("vscode", "esbenp.prettier-vscode", "1.10.0", str(cursor), "editor"),
    ]


def test_list_dir_missing(tmp_path):
    assert userland.list_dir(tmp_path / "nope") == []
