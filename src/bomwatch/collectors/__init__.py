"""Collectors: each one lists the packages of one ecosystem.

A collector returns a list of packages, ``[]`` when its tool is absent, and
``None`` when the tool is present but fails. The collector name is the
ecosystem name, so a diff can leave out the ecosystems that were not scanned.
"""

import sys
from pathlib import Path

from bomwatch.collectors import dpkg, npm, pip
from bomwatch.model import FAILED, OK, SKIPPED

COLLECTORS = {
    "dpkg": dpkg.collect,
    "pip": pip.collect,
    "npm": npm.collect,
}
USES_ROOTS = ("pip",)


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
    packages = set()
    status = {}
    for name, collect in COLLECTORS.items():
        if only and name not in only:
            status[name] = SKIPPED
            continue
        found = run_collector(name, collect, roots)
        status[name] = FAILED if found is None else OK
        packages.update(found or [])
    return sorted(packages), status
