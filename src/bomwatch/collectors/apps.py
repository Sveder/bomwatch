"""Applications that no package manager knows about.

- ``steam``: games and tools (Godot is on Steam) from Steam app manifests.
- ``portable``: executables dropped into the usual download and app folders:
  Windows ``.exe`` files, AppImages and ELF binaries. A ``.exe`` gets the
  version from its version resource, read straight from the file.
- ``macapp``: ``.app`` bundles in ``/Applications`` and ``~/Applications``.
"""

from __future__ import annotations

import os
import plistlib
import re
import stat
import struct
import sys
from pathlib import Path

from bomwatch.model import Package

# ---------------------------------------------------------------- Steam

VDF_PAIR = re.compile(r'"([^"{}\n]+)"\s+"((?:[^"\\\n]|\\.)*)"')


def steam_dirs(home=None):
    """Return the Steam install dirs that exist, symlinks resolved."""
    home = Path.home() if home is None else Path(home)
    found = [
        home / ".steam" / "steam",
        home / ".local" / "share" / "Steam",
        home / ".var" / "app" / "com.valvesoftware.Steam" / ".local/share/Steam",
        home / "Library" / "Application Support" / "Steam",
    ]
    for var in ("ProgramFiles(x86)", "ProgramFiles"):
        if os.environ.get(var):
            found.append(Path(os.environ[var]) / "Steam")
    return sorted({d.resolve() for d in found if (d / "steamapps").is_dir()})


def vdf_values(text, key):
    """Return every value of ``"key" "value"`` pairs in a Valve KeyValues file."""
    return [v.replace("\\\\", "\\") for k, v in VDF_PAIR.findall(text) if k == key]


def read_text(path):
    """Return the text of ``path``, or "" when it cannot be read."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def steam_libraries(home=None):
    """Return every ``steamapps`` dir: each install plus its extra libraries."""
    found = set()
    for install in steam_dirs(home):
        found.add(install / "steamapps")
        vdf = read_text(install / "steamapps" / "libraryfolders.vdf")
        for path in vdf_values(vdf, "path"):
            if (Path(path) / "steamapps").is_dir():
                found.add((Path(path) / "steamapps").resolve())
    return sorted(found)


def read_manifest(path, library):
    """Return the package in one ``appmanifest_<id>.acf``, or None."""
    text = read_text(path)
    name, build = vdf_values(text, "name"), vdf_values(text, "buildid")
    appid = vdf_values(text, "appid")
    if not name:
        return None
    return Package(
        "steam",
        name[0],
        build[0] if build else "",
        str(library),
        f"appid:{appid[0]}" if appid else "steam",
    )


def collect_steam(_roots, home=None):
    """Return the apps installed through Steam."""
    packages = []
    for library in steam_libraries(home):
        for manifest in sorted(library.glob("appmanifest_*.acf")):
            found = read_manifest(manifest, library)
            if found:
                packages.append(found)
    return packages


# ---------------------------------------------------------------- PE version

VS_SIGNATURE = b"\xbd\x04\xef\xfe"
MAX_RESOURCES = 64 * 1024 * 1024


def pe_version(path) -> str:
    """Return the file version of a Windows executable, or "".

    Only the ``.rsrc`` section is read; the version is the ``VS_FIXEDFILEINFO``
    record in it, as ``major.minor.build.revision``.
    """
    try:
        with open(path, "rb") as handle:
            if handle.read(2) != b"MZ":
                return ""
            handle.seek(0x3C)
            (pe_offset,) = struct.unpack("<I", handle.read(4))
            handle.seek(pe_offset)
            if handle.read(4) != b"PE\0\0":
                return ""
            header = handle.read(20)
            sections, optional_size = struct.unpack("<2xH12xH2x", header)
            handle.seek(pe_offset + 24 + optional_size)
            for _ in range(min(sections, 96)):
                entry = handle.read(40)
                if len(entry) < 40:
                    return ""
                name = entry[:8].rstrip(b"\0")
                raw_size, raw_offset = struct.unpack("<II", entry[16:24])
                if name == b".rsrc":
                    handle.seek(raw_offset)
                    return fixed_file_version(handle.read(min(raw_size, MAX_RESOURCES)))
    except (OSError, struct.error):
        return ""
    return ""


def fixed_file_version(data: bytes) -> str:
    """Return the file version from the ``VS_FIXEDFILEINFO`` in ``data``."""
    at = data.find(VS_SIGNATURE)
    if at < 0 or len(data) < at + 16:
        return ""
    high, low = struct.unpack("<II", data[at + 8 : at + 16])
    return f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"


# ---------------------------------------------------------------- portable

PORTABLE_DEPTH = 3
PORTABLE_SKIP = {"node_modules", ".git", "__pycache__", "site-packages"}
EXE_SUFFIXES = {".exe", ".appimage"}


def portable_dirs(home=None):
    """Return the folders where downloaded and unpacked programs usually land."""
    home = Path.home() if home is None else Path(home)
    found = [
        home / name
        for name in ("Downloads", "Desktop", "Applications", "Apps", "bin", "opt")
    ]
    found.append(home / ".local" / "bin")
    if os.environ.get("LOCALAPPDATA"):
        local = Path(os.environ["LOCALAPPDATA"])
        found += [local / "Programs", local / "Microsoft" / "WinGet" / "Packages"]
    return sorted({d for d in found if d.is_dir()})


def is_program(entry: os.DirEntry) -> bool:
    """Return True for a ``.exe``, an AppImage, or an executable ELF file."""
    suffix = os.path.splitext(entry.name)[1].lower()
    if suffix in EXE_SUFFIXES:
        return True
    if sys.platform == "win32":
        return False
    try:
        info = entry.stat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            return False
        with open(entry.path, "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def find_programs(folder, depth=PORTABLE_DEPTH):
    """Yield program paths under ``folder``, ``depth`` levels down at most.

    ``.app`` bundles are left to the ``macapp`` collector.
    """
    try:
        entries = sorted(os.scandir(folder), key=lambda e: e.name)
    except OSError:
        return
    for entry in entries:
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        if is_dir:
            if depth > 1 and entry.name not in PORTABLE_SKIP:
                if not entry.name.endswith(".app"):
                    yield from find_programs(entry.path, depth - 1)
        elif is_program(entry):
            yield Path(entry.path)


def collect_portable(_roots, home=None):
    """Return the programs found in the download and app folders."""
    packages = []
    for folder in portable_dirs(home):
        for program in find_programs(folder):
            version = pe_version(program) if program.suffix.lower() == ".exe" else ""
            packages.append(
                Package("portable", program.name, version, str(program.parent), "file")
            )
    return packages


# ---------------------------------------------------------------- macOS


def app_dirs(home=None):
    """Return ``/Applications`` and ``~/Applications`` when they exist."""
    home = Path.home() if home is None else Path(home)
    return [d for d in (Path("/Applications"), home / "Applications") if d.is_dir()]


def read_bundle(bundle):
    """Return the package of one ``.app`` bundle from its ``Info.plist``."""
    try:
        with open(bundle / "Contents" / "Info.plist", "rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError):
        info = {}
    if not isinstance(info, dict):
        info = {}
    version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
    return Package(
        "macapp",
        bundle.stem,
        str(version or ""),
        str(bundle.parent),
        str(info.get("CFBundleIdentifier", "bundle")),
    )


def collect_macapp(_roots, home=None):
    """Return the ``.app`` bundles in the Applications folders (one level down)."""
    packages = []
    for folder in app_dirs(home):
        for entry in sorted(folder.iterdir()):
            if entry.suffix == ".app":
                packages.append(read_bundle(entry))
            elif entry.is_dir():
                packages += [read_bundle(b) for b in sorted(entry.glob("*.app"))]
    return packages
