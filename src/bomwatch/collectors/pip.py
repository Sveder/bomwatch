"""Python packages from the system interpreter, user-site and every env found.

Envs are read from their metadata files; no interpreter under the roots is run.
"""

import json
import os
import re
import sys
from email.parser import HeaderParser
from pathlib import Path

from bomwatch import walk
from bomwatch.collectors import windows
from bomwatch.model import Package
from bomwatch.runner import run

SYSTEM_PYTHON = "/usr/bin/python3"
LIST_SCRIPT = (
    "import json, importlib.metadata as m\n"
    "print(json.dumps(sorted({(d.metadata['Name'] or '', d.version or '')"
    " for d in m.distributions()})))"
)
MAX_DEPTH = walk.MAX_DEPTH


def normalize(name):
    """Return the PEP 503 normalized form of a package name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def find_envs(roots, max_depth=MAX_DEPTH):
    """Return venv (``pyvenv.cfg``) and conda (``conda-meta/``) dirs under ``roots``."""
    return list(walk.find(roots, max_depth).envs)


def list_dir(path):
    """Return the entries of ``path``, or ``[]`` when it cannot be listed."""
    try:
        return sorted(Path(path).iterdir())
    except OSError:
        return []


def site_dirs(prefix):
    """Return the site-packages dirs of an env or user prefix.

    That is ``lib/python3*/site-packages`` on POSIX and ``Lib/site-packages``
    in a Windows env.
    """
    found = [
        lib / "site-packages"
        for lib in list_dir(Path(prefix) / "lib")
        if lib.name.startswith("python3")
    ]
    windows_site = Path(prefix) / "Lib" / "site-packages"
    if not found and windows_site.is_dir():
        found.append(windows_site)
    return found


def metadata_file(entry):
    """Return the metadata file of a ``.dist-info`` or ``.egg-info`` entry."""
    if entry.suffix == ".dist-info":
        return entry / "METADATA"
    if entry.suffix == ".egg-info":
        return entry / "PKG-INFO" if entry.is_dir() else entry
    return None


def read_metadata(path):
    """Return (name, version) from a metadata file, or None if unreadable."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            headers = HeaderParser().parse(handle)
    except OSError:
        return None
    if not headers["Name"]:
        return None
    return headers["Name"], headers["Version"] or ""


def read_site(site, location, source):
    """Return the packages installed in one site-packages dir."""
    packages = []
    for entry in list_dir(site):
        path = metadata_file(entry)
        found = read_metadata(path) if path else None
        if found:
            name, version = found
            packages.append(Package("pip", normalize(name), version, location, source))
    return packages


def read_prefix(prefix, location, source, tag=False):
    """Return the packages of every site-packages dir under ``prefix``.

    With more than one site dir, or with ``tag``, the location gets a
    ``/python3.N`` suffix so every package key stays unique.
    """
    sites = site_dirs(prefix)
    tag = tag or len(sites) > 1
    return [
        pkg
        for site in sites
        for pkg in read_site(
            site, f"{location}/{site.parent.name}" if tag else location, source
        )
    ]


def parse(output):
    """Turn the JSON printed by LIST_SCRIPT into system packages.

    Returns None when the output is not that JSON: an empty list would count
    as a good scan and report every system package as removed.
    """
    try:
        pairs = json.loads(output)
        if not isinstance(pairs, list):
            return None
    except (TypeError, ValueError):
        return None
    return [
        Package("pip", normalize(name), version, "system", "system")
        for name, version in pairs
        if name
    ]


def system_packages():
    """Return the system interpreter's packages, ``[]`` if absent, None on failure."""
    if not os.path.exists(SYSTEM_PYTHON):
        return []
    output = run([SYSTEM_PYTHON, "-I", "-c", LIST_SCRIPT])
    return None if output is None else parse(output)


def windows_user_sites():
    """Return packages of the Windows user sites, ``%APPDATA%\\Python\\Python3NN``."""
    appdata = os.environ.get("APPDATA")
    if sys.platform != "win32" or not appdata:
        return []
    return [
        pkg
        for version in list_dir(Path(appdata) / "Python")
        if version.name.startswith("Python3")
        for pkg in read_site(
            version / "site-packages", f"user-site/{version.name.lower()}", "user"
        )
    ]


def windows_system_packages(reg=None):
    """Return packages of the Windows interpreters registered per PEP 514.

    Their ``Lib\\site-packages`` dirs are read like any env; no interpreter
    is run. The location is ``system/<install dir name>``, e.g.
    ``system/python312``.
    """
    if reg is None:
        if sys.platform != "win32":
            return []
        import winreg as reg  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,import-error
    return [
        pkg
        for install in windows.python_installs(reg)
        for pkg in read_site(
            Path(install) / "Lib" / "site-packages",
            f"system/{Path(install).name.lower()}",
            "system",
        )
    ]


def collect(roots):
    """Return pip packages, or None if the system interpreter fails."""
    packages = system_packages()
    if packages is None:
        return None
    packages += windows_system_packages()
    packages += read_prefix(Path.home() / ".local", "user-site", "user", tag=True)
    packages += windows_user_sites()
    for env in find_envs(roots):
        source = "conda" if (env / "conda-meta").is_dir() else "venv"
        packages += read_prefix(env, str(env), source)
    return packages
