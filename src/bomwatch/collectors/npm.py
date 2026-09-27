"""Global npm packages, for every nvm node version and the default prefix."""

import json
from pathlib import Path

from bomwatch.model import Package
from bomwatch.runner import has, run


def read_package(package_dir):
    """Return (name, version) from ``package.json``, or None."""
    try:
        data = json.loads((package_dir / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("name"):
        return None
    return data["name"], str(data.get("version", ""))


def list_dir(path):
    """Return the sorted entries of ``path``, or ``[]`` if it cannot be listed."""
    try:
        return sorted(Path(path).iterdir())
    except OSError:
        return []


def package_dirs(node_modules):
    """Yield the package directories directly under ``node_modules``."""
    for entry in list_dir(node_modules):
        if entry.name.startswith("@") and entry.is_dir():
            yield from (p for p in list_dir(entry) if p.is_dir())
        elif entry.is_dir() and not entry.name.startswith("."):
            yield entry


def scan_node_modules(node_modules, source):
    """Return packages installed in one ``node_modules`` directory."""
    node_modules = Path(node_modules)
    if not node_modules.is_dir():
        return []
    packages = []
    for package_dir in package_dirs(node_modules):
        found = read_package(package_dir)
        if found:
            name, version = found
            packages.append(Package("npm", name, version, str(node_modules), source))
    return packages


def global_roots(home=None):
    """Return global ``node_modules`` dirs (nvm and ``npm root -g``), None if npm fails."""
    home = Path.home() if home is None else Path(home)
    roots = set(home.glob(".nvm/versions/node/*/lib/node_modules"))
    if has("npm"):
        output = run(["npm", "root", "-g"])
        if output is None:
            return None
        if output.strip():
            roots.add(Path(output.strip()))
    return sorted(roots)


def collect(_roots, home=None):
    """Return global npm packages, or None if npm is present but fails."""
    roots = global_roots(home)
    if roots is None:
        return None
    packages = []
    for node_modules in roots:
        packages.extend(scan_node_modules(node_modules, "npm-global"))
    return packages
