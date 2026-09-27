"""The story of one package across every saved scan (``bomwatch log``)."""

from __future__ import annotations

import re

from bomwatch import diff, snapshot
from bomwatch.model import OK, Package

MARKS = {
    "added": "+",
    "removed": "-",
    "upgraded": "^",
    "downgraded": "v",
    "changed": "~",
}


def matches(pkg, name, ecosystem=None):
    """Return True when ``pkg`` is called ``name`` (any case, ``-_.`` alike)."""
    if ecosystem and pkg.ecosystem != ecosystem:
        return False

    def norm(text):
        return re.sub(r"[-_.]+", "-", text).lower()

    return norm(pkg.name) == norm(name)


def events(files, name, ecosystem=None, uses_roots=()):
    """Return ``[{created, kind, package, old}]`` for ``name`` over ``files``.

    A scan where the package's collector was not ok says nothing about it,
    so it is not taken as a removal; nor is a scan of other roots for a
    collector in ``uses_roots``.
    """
    seen: dict[tuple, Package] = {}
    seen_roots: dict[tuple, list | None] = {}
    found = []
    for path in files:
        snap = snapshot.try_load(path)
        if snap is None:
            continue
        now = {p.key: p for p in snap["packages"] if matches(p, name, ecosystem)}
        for key in sorted(now.keys() | seen.keys()):
            if snapshot.status(snap, key[0]) != OK:
                continue
            if key[0] in uses_roots and key in seen_roots:
                if not snapshot.same_roots(seen_roots[key], snap["roots"]):
                    continue
            seen_roots[key] = snap["roots"]
            before, after = seen.get(key), now.get(key)
            if before is None and after is not None:
                kind = "added"
            elif after is None and before is not None:
                kind = "removed"
            elif before and after and before.version != after.version:
                kind = diff.change_kind(key[0], before.version, after.version)
            else:
                continue
            found.append(
                {
                    "created": snap["created"],
                    "kind": kind,
                    "package": after or before,
                    "old": before if kind not in ("added", "removed") else None,
                }
            )
            if after is None:
                seen.pop(key)
            else:
                seen[key] = after
    return found


def to_lines(found):
    """Return ``events`` as text lines."""
    lines = []
    for event in found:
        pkg, old = event["package"], event["old"]
        version = f"{old.version} -> {pkg.version}" if old else pkg.version
        lines.append(
            f"{event['created']}  {MARKS[event['kind']]} {pkg.ecosystem} {pkg.name}"
            f" {version} ({pkg.location})"
        )
    return lines


def to_dict(found):
    """Return ``events`` as plain dicts."""
    return [
        {
            "created": e["created"],
            "kind": e["kind"],
            "package": e["package"].to_dict(),
            "old_version": e["old"].version if e["old"] else None,
        }
        for e in found
    ]
