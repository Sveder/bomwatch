"""Collectors: each one lists the packages of one ecosystem.

A collector returns a list of packages, ``[]`` when its tool is absent, and
``None`` when the tool is present but fails. The collector name is the
ecosystem name, so a diff can leave out the ecosystems that were not scanned.
"""

import sys
from pathlib import Path

from bomwatch import walk
from bomwatch.collectors import (
    agents,
    apps,
    autostart,
    containers,
    credentials,
    dpkg,
    npm,
    npm_project,
    pip,
    system,
    userland,
    windows,
)
from bomwatch.model import FAILED, OK, SKIPPED, Package

COLLECTORS = {
    # system packages
    "dpkg": dpkg.collect,
    "rpm": system.collect_rpm,
    "snap": system.collect_snap,
    "flatpak": system.collect_flatpak,
    "brew": userland.collect_brew,
    # language packages
    "pip": pip.collect,
    "npm": npm.collect,
    "npm-project": npm_project.collect,
    "cargo": userland.collect_cargo,
    "go": userland.collect_go,
    # containers and editors
    "docker": containers.collect_docker,
    "podman": containers.collect_podman,
    "vscode": userland.collect_vscode,
    # applications
    "steam": apps.collect_steam,
    "portable": apps.collect_portable,
    "macapp": apps.collect_macapp,
    "windows": windows.collect_windows,
    "appx": windows.collect_appx,
    "scoop": windows.collect_scoop,
    "choco": windows.collect_choco,
    # what runs later, who can log in, what agents may do and are told
    "autostart": autostart.collect,
    "credential": credentials.collect,
    "mcp": agents.collect_mcp,
    "agent-config": agents.collect_config,
    "agent-memory": agents.collect_memory,
}
USES_ROOTS = ("pip", "npm-project", "mcp", "agent-config", "agent-memory")


def default_roots():
    """Return the directories searched for environments by default."""
    return [Path.home()]


def resolve_roots(roots=None):
    """Return ``roots`` as sorted absolute paths, or the default roots."""
    roots = default_roots() if roots is None else roots
    return sorted({Path(r).absolute() for r in roots})


def run_collector(name, collect, roots):
    """Run one collector; an ``OSError`` counts as a failure, not a crash."""
    try:
        return collect(roots)
    except OSError as error:
        print(f"collector {name}: {error}", file=sys.stderr)
        return None


def collect_all(roots=None, only=None):
    """Run the collectors and return (sorted packages, {collector: status})."""
    roots = resolve_roots(roots)
    walk.clear()
    packages: set[Package] = set()
    status = {}
    for name, collect in COLLECTORS.items():
        if only and name not in only:
            status[name] = SKIPPED
            continue
        found = run_collector(name, collect, roots)
        status[name] = FAILED if found is None else OK
        packages.update(found or [])
    return sorted(packages), status
