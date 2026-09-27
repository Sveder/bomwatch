import os
import plistlib
import struct
import sys

import pytest

from bomwatch.collectors import apps
from bomwatch.model import Package


def make_pe(path, version=(4, 3, 0, 0), rsrc=True):
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x40)
    data[0x40:0x44] = b"PE\0\0"
    data[0x42 + 2 + 2 : 0x42 + 2 + 4] = b""  # layout below
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
    data[0x44 : 0x44 + 20] = coff
    name = b".rsrc\0\0\0" if rsrc else b".text\0\0\0"
    section = name + struct.pack("<IIII", 0x100, 0x1000, 0x100, 0x100) + bytes(16)
    data[0x58 : 0x58 + 40] = section
    major, minor, build, rev = version
    fixed = apps.VS_SIGNATURE + struct.pack(
        "<III", 0x10000, (major << 16) | minor, (build << 16) | rev
    )
    data[0x120 : 0x120 + len(fixed)] = fixed
    path.write_bytes(bytes(data))
    return path


def test_pe_version(tmp_path):
    assert (
        apps.pe_version(make_pe(tmp_path / "Godot_v4.3-stable_win64.exe")) == "4.3.0.0"
    )
    assert apps.pe_version(make_pe(tmp_path / "t.exe", rsrc=False)) == ""
    (tmp_path / "text.exe").write_bytes(b"hello")
    assert apps.pe_version(tmp_path / "text.exe") == ""
    bad = bytearray(make_pe(tmp_path / "bad.exe").read_bytes())
    bad[0x40:0x44] = b"XXXX"
    (tmp_path / "bad.exe").write_bytes(bytes(bad))
    assert apps.pe_version(tmp_path / "bad.exe") == ""
    (tmp_path / "short.exe").write_bytes(
        b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0" + bytes(20)
    )
    assert apps.pe_version(tmp_path / "short.exe") == ""
    assert apps.pe_version(tmp_path / "missing.exe") == ""
    assert apps.fixed_file_version(b"nothing here") == ""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX exec bits")
def test_portable_finds_programs(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    downloads = tmp_path / "Downloads"
    (downloads / "Godot_v4.3-stable_win64").mkdir(parents=True)
    make_pe(downloads / "Godot_v4.3-stable_win64" / "Godot_v4.3-stable_win64.exe")
    (downloads / "Tool.AppImage").write_bytes(b"\x7fELF....")
    elf = tmp_path / ".local" / "bin" / "uv"
    elf.parent.mkdir(parents=True)
    elf.write_bytes(b"\x7fELF....")
    elf.chmod(0o755)
    script = elf.parent / "script"
    script.write_text("#!/bin/sh\n")
    script.chmod(0o755)
    (elf.parent / "noexec").write_bytes(b"\x7fELF")
    (downloads / "notes.txt").write_text("")
    (downloads / "node_modules").mkdir()
    make_pe(downloads / "node_modules" / "skip.exe")
    (downloads / "Some.app").mkdir()
    make_pe(downloads / "Some.app" / "inner.exe")
    deep = downloads / "a" / "b" / "c"
    deep.mkdir(parents=True)
    make_pe(deep / "deep.exe")
    os.symlink(elf, downloads / "link-to-uv")
    assert apps.collect_portable([], home=tmp_path) == [
        Package("portable", "uv", "", str(elf.parent), "file"),
        Package(
            "portable",
            "Godot_v4.3-stable_win64.exe",
            "4.3.0.0",
            str(downloads / "Godot_v4.3-stable_win64"),
            "file",
        ),
        Package("portable", "Tool.AppImage", "", str(downloads), "file"),
        Package("portable", "link-to-uv", "", str(downloads), "file"),
    ]


def test_portable_dirs_windows(tmp_path, monkeypatch):
    local = tmp_path / "Local"
    (local / "Programs").mkdir(parents=True)
    (local / "Microsoft" / "WinGet" / "Packages").mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    assert apps.portable_dirs(tmp_path) == [
        local / "Microsoft" / "WinGet" / "Packages",
        local / "Programs",
    ]


def test_find_programs_missing_dir(tmp_path):
    assert not list(apps.find_programs(tmp_path / "nope"))


def test_is_program_on_windows_needs_suffix(tmp_path, monkeypatch):
    (tmp_path / "tool").write_bytes(b"\x7fELF")
    monkeypatch.setattr(apps.sys, "platform", "win32")
    entry = next(os.scandir(tmp_path))
    assert not apps.is_program(entry)


MANIFEST = """"AppState"
{
\t"appid"\t\t"404790"
\t"name"\t\t"Godot Engine"
\t"buildid"\t\t"15432100"
}
"""


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need admin on Windows")
def test_steam(tmp_path, monkeypatch):
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "pf"))
    steam = tmp_path / ".local" / "share" / "Steam" / "steamapps"
    steam.mkdir(parents=True)
    (tmp_path / ".steam").mkdir()
    os.symlink(tmp_path / ".local" / "share" / "Steam", tmp_path / ".steam" / "steam")
    extra = tmp_path / "games"
    (extra / "steamapps").mkdir(parents=True)
    (steam / "libraryfolders.vdf").write_text(
        f'"libraryfolders"\n{{\n "1"\n {{\n  "path"\t\t"{extra}"\n }}\n'
        f' "2" {{ "path" "{tmp_path / "gone"}" }}\n}}\n'
    )
    (steam / "appmanifest_404790.acf").write_text(MANIFEST)
    (extra / "steamapps" / "appmanifest_1.acf").write_text(
        '"AppState" { "name" "NoBuild" }'
    )
    (extra / "steamapps" / "appmanifest_2.acf").write_text('"AppState" { }')
    assert apps.collect_steam([], home=tmp_path) == [
        Package(
            "steam", "Godot Engine", "15432100", str(steam.resolve()), "appid:404790"
        ),
        Package("steam", "NoBuild", "", str(extra.resolve() / "steamapps"), "steam"),
    ]
    assert apps.read_text(tmp_path / "missing") == ""


def test_macapp(tmp_path, monkeypatch):
    monkeypatch.setattr(apps, "Path", apps.Path)
    folder = tmp_path / "Applications"
    godot = folder / "Godot.app" / "Contents"
    godot.mkdir(parents=True)
    with open(godot / "Info.plist", "wb") as handle:
        plistlib.dump(
            {
                "CFBundleShortVersionString": "4.3",
                "CFBundleIdentifier": "org.godotengine.godot",
            },
            handle,
        )
    (folder / "Broken.app").mkdir()
    (folder / "Utilities" / "Tool.app" / "Contents").mkdir(parents=True)
    (folder / "Utilities" / "Tool.app" / "Contents" / "Info.plist").write_bytes(
        plistlib.dumps(["not", "a", "dict"])
    )
    (folder / "readme.txt").write_text("")
    found = [
        p
        for p in apps.collect_macapp([], home=tmp_path)
        if p.location.startswith(str(tmp_path))
    ]
    assert found == [
        Package("macapp", "Broken", "", str(folder), "bundle"),
        Package("macapp", "Godot", "4.3", str(folder), "org.godotengine.godot"),
        Package("macapp", "Tool", "", str(folder / "Utilities"), "bundle"),
    ]
