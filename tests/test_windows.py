# pylint: disable=invalid-name
import json

from bomwatch.collectors import pip, windows
from bomwatch.model import Package


class Key:
    """A registry key: values and named subkeys."""

    def __init__(self, values=None, children=None):
        self.values = values or {}
        self.children = children or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeWinreg:
    """Just enough of ``winreg`` for the Uninstall keys."""

    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 1
    KEY_WOW64_64KEY = 0x100
    KEY_WOW64_32KEY = 0x200

    def __init__(self, views):
        self.views = views

    def OpenKey(self, parent, name, _reserved=0, access=KEY_READ):  # noqa: N802
        if isinstance(parent, Key):
            if name not in parent.children:
                raise FileNotFoundError(name)
            return parent.children[name]
        view = (parent, access)
        if view not in self.views:
            raise FileNotFoundError(name)
        return self.views[view]

    def EnumKey(self, key, index):  # noqa: N802
        names = list(key.children)
        if index >= len(names):
            raise OSError("no more")
        return names[index]

    def QueryValueEx(self, key, name):  # noqa: N802
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], 1


def uninstall(**entries):
    return Key(children={name: Key(values) for name, values in entries.items()})


def test_registry_lists_visible_programs():
    reg = FakeWinreg(
        {
            ("HKLM", 1 | 0x100): uninstall(
                Godot={
                    "DisplayName": "Godot Engine ",
                    "DisplayVersion": "4.3",
                    "Publisher": "Godot",
                },
                Hidden={"DisplayName": "Runtime", "SystemComponent": 1},
                Patch={"DisplayName": "Update", "ParentKeyName": "Office"},
                Hotfix={"DisplayName": "KB1", "ReleaseType": "Hotfix"},
                Blank={"DisplayVersion": "1"},
            ),
            ("HKCU", 1): uninstall(
                GodotEngine={"DisplayName": "Godot Engine", "DisplayVersion": "4.3"},
            ),
        }
    )
    reg.views[("HKLM", 1 | 0x100)].children["Gone"] = None  # unreadable subkey
    real_open = reg.OpenKey

    def open_key(parent, name, *args):
        if isinstance(parent, Key) and parent.children.get(name, 0) is None:
            raise PermissionError(name)
        return real_open(parent, name, *args)

    reg.OpenKey = open_key
    assert windows.collect_windows([], reg=reg) == [
        Package("windows", "Godot Engine", "4.3", "machine-x64", "Godot"),
        Package("windows", "Godot Engine", "4.3", "user", "registry"),
    ]


def test_collect_windows_off_windows(monkeypatch):
    monkeypatch.setattr(windows.sys, "platform", "linux")
    assert windows.collect_windows([]) == []


def test_appx(monkeypatch):
    data = [
        {
            "Name": "Microsoft.WindowsTerminal",
            "Version": "1.20.1",
            "Architecture": 9,
            "IsFramework": False,
        },
        {
            "Name": "Microsoft.VCLibs.140.00",
            "Version": "14.0",
            "Architecture": 9,
            "IsFramework": True,
        },
        {"Version": "1"},
        "junk",
    ]
    assert windows.parse_appx(json.dumps(data)) == [
        Package("appx", "Microsoft.WindowsTerminal", "1.20.1", "9", "store"),
        Package("appx", "Microsoft.VCLibs.140.00", "14.0", "9", "framework"),
    ]
    assert (
        windows.parse_appx(json.dumps(data[0]))[0].name == "Microsoft.WindowsTerminal"
    )
    assert windows.parse_appx("") == []
    assert windows.parse_appx("not json") is None
    assert windows.parse_appx("3") == []
    monkeypatch.setattr(windows.sys, "platform", "win32")
    monkeypatch.setattr(windows, "has", lambda tool: True)
    monkeypatch.setattr(windows, "run", lambda cmd: json.dumps(data[:1]))
    assert len(windows.collect_appx([])) == 1
    monkeypatch.setattr(windows, "run", lambda cmd: None)
    assert windows.collect_appx([]) is None
    monkeypatch.setattr(windows.sys, "platform", "linux")
    assert windows.collect_appx([]) == []


def test_scoop(tmp_path, monkeypatch):
    monkeypatch.delenv("SCOOP", raising=False)
    monkeypatch.setenv("ProgramData", str(tmp_path / "pd"))
    monkeypatch.delenv("SCOOP_GLOBAL", raising=False)
    apps = tmp_path / "scoop" / "apps"
    (apps / "godot" / "current").mkdir(parents=True)
    (apps / "godot" / "current" / "manifest.json").write_text(
        "\ufeff" + json.dumps({"version": "4.3"}), encoding="utf-8"
    )
    (apps / "broken" / "current").mkdir(parents=True)
    (apps / "broken" / "current" / "manifest.json").write_text("{")
    (apps / "list" / "current").mkdir(parents=True)
    (apps / "list" / "current" / "manifest.json").write_text("[]")
    assert windows.collect_scoop([], home=tmp_path) == [
        Package("scoop", "godot", "4.3", str(tmp_path / "scoop"), "scoop")
    ]


def test_choco(tmp_path, monkeypatch):
    lib = tmp_path / "choco" / "lib"
    (lib / "Godot").mkdir(parents=True)
    (lib / "Godot" / "Godot.nuspec").write_text(
        "<package><metadata><id>godot</id><version> 4.3.0 </version></metadata></package>"
    )
    (lib / "noversion").mkdir()
    (lib / "noversion" / "noversion.nuspec").write_text("<package/>")
    (lib / "nonuspec").mkdir()
    assert windows.collect_choco([], lib=lib) == [
        Package("choco", "godot", "4.3.0", str(lib), "choco")
    ]
    monkeypatch.setenv("ChocolateyInstall", str(tmp_path / "choco"))
    assert windows.choco_lib() == lib
    assert len(windows.collect_choco([])) == 1
    assert not windows.collect_choco([], lib=tmp_path / "nope")


def python_core(**installs):
    return Key(
        children={
            tag: Key(children={} if path is None else {"InstallPath": Key({"": path})})
            for tag, path in installs.items()
        }
    )


def test_python_installs_and_system_packages(tmp_path):
    install = tmp_path / "Python312"
    dist = install / "Lib" / "site-packages" / "requests-2.32.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: requests\nVersion: 2.32.0\n")
    reg = FakeWinreg(
        {
            ("HKLM", 1 | 0x100): python_core(
                **{"3.12": str(install), "2.7": "C:/Py27"}
            ),
            ("HKCU", 1): python_core(**{"3.13": "", "3.11": None}),
        }
    )
    assert windows.python_installs(reg) == [str(install)]
    assert pip.windows_system_packages(reg) == [
        Package("pip", "requests", "2.32.0", "system/python312", "system")
    ]


def test_windows_system_packages_off_windows(monkeypatch):
    monkeypatch.setattr(pip.sys, "platform", "linux")
    assert not pip.windows_system_packages()
