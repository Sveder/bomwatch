"""Compare two package lists."""

from bomwatch import versions
from bomwatch.model import OK

CHANGE_KINDS = ("added", "removed", "upgraded", "downgraded", "changed")
PAIR_MARKS = (("upgraded", "^"), ("downgraded", "v"), ("changed", "~"))
# A new or changed record of these ecosystems is an alert even without flags.
ALERT_ECOSYSTEMS = frozenset({"credential"})


def change_kind(ecosystem, old, new):
    """Return ``upgraded``, ``downgraded`` or ``changed`` (no order) for a new version."""
    order = versions.compare(ecosystem, new, old)
    if order is None:
        return "changed"
    return "downgraded" if order < 0 else "upgraded"


def not_compared(old_status, new_status):
    """Return ``{ecosystem: reason}`` for ecosystems not scanned ok in both snapshots.

    A collector missing from a status map counts as ok (schema 1 snapshots).
    """
    result = {}
    for name in sorted(set(old_status) | set(new_status)):
        sides = {"OLD": old_status.get(name, OK), "NEW": new_status.get(name, OK)}
        reasons = [
            f"{status} in {side}" for side, status in sides.items() if status != OK
        ]
        if reasons:
            result[name] = ", ".join(reasons)
    return result


def noteworthy(reason):
    """Return False for a collector that ran on neither side (skipped or not
    run in both): there was nothing to compare, so a note says nothing."""
    parts = reason.split(", ")
    return len(parts) < 2 or not all(
        p.startswith(("skipped", "not run")) for p in parts
    )


def roots_differ(old_roots, new_roots, uses_roots):
    """Return ``{ecosystem: "roots differ"}`` when both root lists are known and differ."""
    if old_roots is None or new_roots is None or old_roots == new_roots:
        return {}
    return {name: "roots differ" for name in sorted(uses_roots)}


def compare(old, new, skip=()):
    """Return the changes from package list ``old`` to ``new``, ignoring ``skip``."""
    before = {p.key: p for p in old if p.ecosystem not in skip}
    after = {p.key: p for p in new if p.ecosystem not in skip}
    result = {
        "added": [after[k] for k in sorted(after.keys() - before.keys())],
        "removed": [before[k] for k in sorted(before.keys() - after.keys())],
        "upgraded": [],
        "downgraded": [],
        "changed": [],
    }
    for key in sorted(before.keys() & after.keys()):
        was, now = before[key], after[key]
        if was.version != now.version:
            kind = change_kind(now.ecosystem, was.version, now.version)
            result[kind].append({"old": was, "new": now})
    return result


def is_empty(changes):
    """Return True when ``changes`` holds no change."""
    return not any(changes.get(kind) for kind in CHANGE_KINDS)


def new_packages(changes):
    """Return the packages that are new or at a new version in ``changes``."""
    found = list(changes["added"])
    for kind, _ in PAIR_MARKS:
        found += [item["new"] for item in changes[kind]]
    return sorted(found)


def alerts(changes):
    """Return the new or changed records that need a look: flagged ones, and
    every credential."""
    return [
        p for p in new_packages(changes) if p.flags or p.ecosystem in ALERT_ECOSYSTEMS
    ]


def tag(pkg):
    """Return `` [flags]`` for a flagged record, else ""."""
    return f" [{pkg.flags}]" if pkg.flags else ""


def plain(item):
    """Return a package, or an ``{"old", "new"}`` pair, as plain dicts."""
    if isinstance(item, dict):
        return {side: pkg.to_dict() for side, pkg in item.items()}
    return item.to_dict()


def to_dict(changes):
    """Return ``changes`` with every package turned into a plain dict."""
    return {kind: [plain(i) for i in items] for kind, items in changes.items()}


def to_lines(changes):
    """Return ``changes`` as short text lines, one per change."""
    lines = []
    for kind, mark in (("added", "+"), ("removed", "-")):
        lines += [
            f"{mark} {p.ecosystem} {p.name}{' ' + p.version if p.version else ''}"
            f" ({p.location})" + (tag(p) if mark == "+" else "")
            for p in changes[kind]
        ]
    for kind, mark in PAIR_MARKS:
        for item in changes[kind]:
            old, new = item["old"], item["new"]
            lines.append(
                f"{mark} {new.ecosystem} {new.name} {old.version} -> {new.version}"
                f" ({new.location}){tag(new)}"
            )
    return lines
