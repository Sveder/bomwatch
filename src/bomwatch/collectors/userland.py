"""Tools installed per user: Homebrew, cargo, go binaries and editor extensions.

Everything here is read from files on disk; only ``go version -m`` runs a
tool, and it reads the binaries without executing them.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from bomwatch import versions
from bomwatch.model import Package
from bomwatch.runner import has, run

BREW_PREFIXES = ("/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew")
EDITORS = (
    ".vscode",
    ".vscode-insiders",
    ".vscode-server",
    ".vscode-oss",
    ".cursor",
    ".cursor-server",
    ".windsurf",
)


def list_dir(path):
    """Return the sorted entries of ``path``, or ``[]`` if it cannot be listed."""
    try:
        return sorted(Path(path).iterdir())
    except OSError:
        return []


def read_json(path):
    """Return the parsed JSON file at ``path``, or None."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def newest(names, ecosystem):
    """Return the highest version in ``names``."""
    best = names[0]
    for name in names[1:]:
        if (versions.compare(ecosystem, name, best) or 0) > 0:
            best = name
    return best


# ---------------------------------------------------------------- Homebrew


def brew_prefixes(home=None):
    """Return the Homebrew prefixes that exist."""
    home = Path.home() if home is None else Path(home)
    found = [Path(p) for p in BREW_PREFIXES] + [home / ".linuxbrew"]
    if os.environ.get("HOMEBREW_PREFIX"):
        found.insert(0, Path(os.environ["HOMEBREW_PREFIX"]))
    return sorted({p for p in found if (p / "Cellar").is_dir()})


def read_keg_dir(folder, prefix, source):
    """Return one package per ``<folder>/<name>/<version>``, newest version."""
    packages = []
    for formula in list_dir(folder):
        kegs = [k.name for k in list_dir(formula) if k.is_dir()]
        if kegs:
            version = newest(kegs, "brew")
            packages.append(Package("brew", formula.name, version, prefix, source))
    return packages


def collect_brew(_roots, home=None):
    """Return Homebrew formulae and casks, read from the Cellar and Caskroom."""
    packages = []
    for prefix in brew_prefixes(home):
        packages += read_keg_dir(prefix / "Cellar", str(prefix), "formula")
        packages += read_keg_dir(prefix / "Caskroom", str(prefix), "cask")
    return packages


# ---------------------------------------------------------------- cargo

CRATE = re.compile(r"^(\S+) (\S+) \((.*)\)$")


def cargo_home(home=None):
    """Return ``$CARGO_HOME`` or ``~/.cargo``."""
    if os.environ.get("CARGO_HOME"):
        return Path(os.environ["CARGO_HOME"])
    return (Path.home() if home is None else Path(home)) / ".cargo"


def parse_crates(keys, location):
    """Turn ``"name version (source)"`` keys into packages."""
    packages = []
    for key in keys:
        match = CRATE.match(key)
        if match:
            name, version, source = match.groups()
            kind = source.split("+", 1)[0]
            packages.append(Package("cargo", name, version, location, kind))
    return packages


def collect_cargo(_roots, home=None):
    """Return crates installed with ``cargo install``."""
    base = cargo_home(home)
    data = read_json(base / ".crates2.json")
    if isinstance(data, dict) and isinstance(data.get("installs"), dict):
        return parse_crates(data["installs"], str(base))
    try:
        text = (base / ".crates.toml").read_text(encoding="utf-8")
    except OSError:
        return []
    keys = re.findall(r'^"(.+)"\s*=', text, re.MULTILINE)
    return parse_crates(keys, str(base))


# ---------------------------------------------------------------- go


def go_bin_dirs(home=None):
    """Return the dirs ``go install`` writes to: $GOBIN, $GOPATH/bin, ~/go/bin."""
    home = Path.home() if home is None else Path(home)
    found = []
    if os.environ.get("GOBIN"):
        found.append(Path(os.environ["GOBIN"]))
    for gopath in os.environ.get("GOPATH", "").split(os.pathsep):
        if gopath:
            found.append(Path(gopath) / "bin")
    found.append(home / "go" / "bin")
    return sorted({d for d in found if d.is_dir()})


def parse_go(output):
    """Turn ``go version -m DIR`` output into packages.

    The name is the main package path, the version that of its module, or the
    Go toolchain version for a binary built outside a module. The source is
    the module path, which is what Go advisories name.
    """
    packages: list[Package] = []
    binary = toolchain = path = module = None
    version = ""

    def flush():
        if binary and path:
            packages.append(
                Package("go", path, version or toolchain or "", binary, module or "go")
            )

    for line in output.splitlines():
        if not line.startswith("\t"):
            flush()
            binary, _, toolchain = line.partition(": ")
            toolchain = toolchain.strip()
            path, module, version = None, None, ""
            continue
        fields = line.strip().split("\t")
        if fields[0] == "path" and len(fields) > 1:
            path = fields[1]
        elif fields[0] == "mod" and len(fields) > 2:
            module = fields[1]
            version = "" if fields[2] == "(devel)" else fields[2]
    flush()
    return packages


def collect_go(_roots, home=None):
    """Return binaries installed with ``go install``; [] without the go tool."""
    dirs = go_bin_dirs(home)
    if not dirs or not has("go"):
        return []
    packages = []
    for folder in dirs:
        output = run(["go", "version", "-m", str(folder)])
        if output is None:
            return None
        packages += parse_go(output)
    return packages


# ---------------------------------------------------------------- editors


def read_extensions(folder):
    """Return the extensions in one editor's ``extensions`` dir.

    ``extensions.json`` lists what the editor has enabled; without it every
    ``publisher.name-version`` dir counts, newest version per extension.
    """
    listing = read_json(folder / "extensions.json")
    if isinstance(listing, list):
        packages = []
        for item in listing:
            try:
                ext_id, version = item["identifier"]["id"], item["version"]
            except (KeyError, TypeError):
                continue
            packages.append(
                Package("vscode", ext_id.lower(), str(version), str(folder), "editor")
            )
        return packages
    found: dict[str, list[str]] = {}
    for entry in list_dir(folder):
        data = read_json(entry / "package.json") if entry.is_dir() else None
        if not isinstance(data, dict) or not data.get("name"):
            continue
        ext_id = f"{data.get('publisher', '')}.{data['name']}".lower()
        found.setdefault(ext_id, []).append(str(data.get("version", "")))
    return [
        Package("vscode", ext_id, newest(vers, "vscode"), str(folder), "editor")
        for ext_id, vers in sorted(found.items())
    ]


def collect_vscode(_roots, home=None):
    """Return VS Code, Cursor, Windsurf and VSCodium extensions."""
    home = Path.home() if home is None else Path(home)
    packages = []
    for editor in EDITORS:
        folder = home / editor / "extensions"
        if folder.is_dir():
            packages += read_extensions(folder)
    return packages
