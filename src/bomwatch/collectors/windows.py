"""Windows software: installed programs, Store apps, Scoop and Chocolatey.

- ``windows``: the "Installed apps" list, read from the Uninstall keys of the
  registry (machine 64 and 32 bit, and the current user). Installers, MSI
  packages and winget all register there.
- ``appx``: Microsoft Store and MSIX packages, from ``Get-AppxPackage``.
- ``scoop``: ``~/scoop/apps/<app>/current/manifest.json``, user and global.
- ``choco``: the ``.nuspec`` of each package in Chocolatey's ``lib`` dir.

All four return ``[]`` on other systems.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from bomwatch.model import Package
from bomwatch.runner import has, run

UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
APPX_SCRIPT = (
    "Get-AppxPackage | Select-Object Name,Version,Architecture,IsFramework"
    " | ConvertTo-Json -Compress"
)


def is_windows() -> bool:
    """Return True on Windows."""
    return sys.platform == "win32"


# ---------------------------------------------------------------- registry


def uninstall_views(reg):
    """Return ``(location, hive, access)`` for each Uninstall view to read."""
    wow64_64 = getattr(reg, "KEY_WOW64_64KEY", 0)
    wow64_32 = getattr(reg, "KEY_WOW64_32KEY", 0)
    read = reg.KEY_READ
    return [
        ("machine-x64", reg.HKEY_LOCAL_MACHINE, read | wow64_64),
        ("machine-x86", reg.HKEY_LOCAL_MACHINE, read | wow64_32),
        ("user", reg.HKEY_CURRENT_USER, read),
    ]


PYTHON_CORE = r"SOFTWARE\Python\PythonCore"


def python_installs(reg):
    """Return the install dirs of the Python 3 interpreters registered per PEP 514.

    python.org installers, the ``py`` launcher and most tools record each
    interpreter under ``PythonCore\\<tag>\\InstallPath``.
    """
    found = set()
    for _, hive, access in uninstall_views(reg):
        try:
            core = reg.OpenKey(hive, PYTHON_CORE, 0, access)
        except OSError:
            continue
        with core:
            for tag in list(subkeys(reg, core)):
                if not tag.startswith("3"):
                    continue
                path = install_path(reg, core, tag)
                if path:
                    found.add(path)
    return sorted(found)


def install_path(reg, core, tag):
    """Return the ``InstallPath`` of one ``PythonCore\\<tag>`` key, or None."""
    try:
        with (
            reg.OpenKey(core, tag) as version,
            reg.OpenKey(version, "InstallPath") as key,
        ):
            path = value(reg, key, "")
    except OSError:
        return None
    return str(path) if path else None


def value(reg, key, name):
    """Return one registry value, or None when it is not there."""
    try:
        return reg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def subkeys(reg, key):
    """Yield the names of the subkeys of an open key."""
    index = 0
    while True:
        try:
            yield reg.EnumKey(key, index)
        except OSError:
            return
        index += 1


def read_entry(reg, parent, name, location):
    """Return the package of one Uninstall entry, or None for hidden entries.

    Entries without a display name, system components and updates of other
    entries are not shown in "Installed apps", so they are left out too.
    """
    try:
        key = reg.OpenKey(parent, name)
    except OSError:
        return None
    with key:
        display = value(reg, key, "DisplayName")
        if not display or value(reg, key, "SystemComponent") == 1:
            return None
        if value(reg, key, "ParentKeyName") or value(reg, key, "ReleaseType"):
            return None
        version = value(reg, key, "DisplayVersion") or ""
        publisher = value(reg, key, "Publisher") or "registry"
    return Package(
        "windows", str(display).strip(), str(version).strip(), location, str(publisher)
    )


def read_registry(reg):
    """Return every visible program in the Uninstall keys of all views."""
    packages = set()
    for location, hive, access in uninstall_views(reg):
        try:
            root = reg.OpenKey(hive, UNINSTALL, 0, access)
        except OSError:
            continue
        with root:
            for name in list(subkeys(reg, root)):
                found = read_entry(reg, root, name, location)
                if found:
                    packages.add(found)
    return sorted(packages)


def collect_windows(_roots, reg=None):
    """Return the installed programs; [] when not on Windows."""
    if reg is None:
        if not is_windows():
            return []
        import winreg as reg  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,import-error
    return read_registry(reg)


# ---------------------------------------------------------------- appx


def parse_appx(output):
    """Turn the JSON of ``Get-AppxPackage`` into packages; None if it is not JSON."""
    if not output.strip():
        return []
    try:
        data = json.loads(output)
    except ValueError:
        return None
    if isinstance(data, dict):
        data = [data]
    packages = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict) or not item.get("Name"):
            continue
        source = "framework" if item.get("IsFramework") else "store"
        packages.append(
            Package(
                "appx",
                item["Name"],
                str(item.get("Version") or ""),
                str(item.get("Architecture") or ""),
                source,
            )
        )
    return packages


def collect_appx(_roots):
    """Return Store and MSIX packages of the current user; [] off Windows."""
    if not is_windows() or not has("powershell"):
        return []
    output = run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", APPX_SCRIPT]
    )
    return None if output is None else parse_appx(output)


# ---------------------------------------------------------------- scoop


def scoop_roots(home=None):
    """Return the Scoop roots: $SCOOP or ~/scoop, and $SCOOP_GLOBAL."""
    home = Path.home() if home is None else Path(home)
    found = [Path(os.environ.get("SCOOP") or home / "scoop")]
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    found.append(Path(os.environ.get("SCOOP_GLOBAL") or Path(program_data) / "scoop"))
    return [r for r in found if (r / "apps").is_dir()]


def collect_scoop(_roots, home=None):
    """Return the apps installed with Scoop."""
    packages = []
    for root in scoop_roots(home):
        for app in sorted((root / "apps").iterdir()):
            manifest = app / "current" / "manifest.json"
            try:
                data = json.loads(manifest.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                version = str(data.get("version", ""))
                packages.append(Package("scoop", app.name, version, str(root), "scoop"))
    return packages


# ---------------------------------------------------------------- chocolatey

NUSPEC_VERSION = re.compile(r"<version>\s*([^<\s]+)\s*</version>")


def choco_lib():
    """Return Chocolatey's ``lib`` dir: $ChocolateyInstall or the default."""
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    base = os.environ.get("ChocolateyInstall") or str(Path(program_data) / "chocolatey")
    return Path(base) / "lib"


def collect_choco(_roots, lib=None):
    """Return the packages installed with Chocolatey."""
    lib = choco_lib() if lib is None else Path(lib)
    if not lib.is_dir():
        return []
    packages = []
    for package in sorted(lib.iterdir()):
        nuspec = package / f"{package.name}.nuspec"
        try:
            match = NUSPEC_VERSION.search(nuspec.read_text(encoding="utf-8-sig"))
        except OSError:
            continue
        if match:
            packages.append(
                Package("choco", package.name.lower(), match[1], str(lib), "choco")
            )
    return packages
