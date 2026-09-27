"""Save and load scans as timestamped JSON files."""

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from bomwatch.model import OK, Package

SCHEMA = 3
OTHER_ROOTS = "other roots"


def state_dir(path=None):
    """Return the state dir: ``path``, then $BOMWATCH_STATE_DIR, then the XDG default."""
    if path:
        return Path(path)
    if os.environ.get("BOMWATCH_STATE_DIR"):
        return Path(os.environ["BOMWATCH_STATE_DIR"])
    return Path.home() / ".local" / "state" / "bomwatch"


def snapshot_dir(base):
    """Return the directory that holds the scan files."""
    return Path(base) / "snapshots"


def make(packages, status=None, roots=None, now=None, host=None):
    """Return a snapshot dict for ``packages``, the ``{collector: status}`` map
    and the searched ``roots``."""
    now = now or datetime.now(timezone.utc)
    return {
        "schema": SCHEMA,
        "collectors": dict(sorted((status or {}).items())),
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host or socket.gethostname(),
        "packages": [p.to_dict() for p in sorted(packages)],
        "roots": sorted(str(r) for r in roots) if roots is not None else None,
    }


def save(snap, base):
    """Write ``snap`` into the state dir and return the file path."""
    folder = snapshot_dir(base)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = snap["created"].replace("-", "").replace(":", "")
    path = folder / f"scan-{stamp}.json"
    count = 0
    while path.exists():
        count += 1
        path = folder / f"scan-{stamp}-{count}.json"
    path.write_text(json.dumps(snap, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    return path


def load(path):
    """Read a snapshot file and return it with ``Package`` records.

    Schema 1 files hold no collector status; every collector counts as ok.
    Files before schema 3 hold no roots (``None``, unknown).
    Raises ValueError when the file is not a bomwatch snapshot.
    """
    try:
        snap = json.loads(Path(path).read_text(encoding="utf-8"))
        snap["packages"] = [Package(**p) for p in snap["packages"]]
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"not a bomwatch snapshot: {path}") from exc
    snap.setdefault("collectors", {})
    snap.setdefault("roots", None)
    return snap


def history(base):
    """Return the saved scan files, oldest first."""
    return sorted(snapshot_dir(base).glob("scan-*.json"), key=scan_order)


def scan_order(path):
    """Sort key for a scan file: its time stamp, then its same-second counter."""
    stamp, _, count = path.stem.partition("Z")
    count = count.lstrip("-")
    return stamp, int(count) if count.isdigit() else 0


def same_roots(one, other):
    """Return True unless both root lists are known and differ."""
    return one is None or other is None or one == other


def baseline(files, wanted, roots=None, uses_roots=()):
    """Return the snapshot to diff against, built from ``files`` (oldest first).

    Each collector in ``wanted`` takes its packages from the newest file where it
    was ok, so a change made while it was skipped or failed is still reported.
    A collector in ``uses_roots`` only takes a file scanned with the same ``roots``;
    when no such file exists its status is ``OTHER_ROOTS``.
    Other collectors keep the status of the newest file.
    """
    snap, todo = None, set(wanted)
    for path in reversed(files):
        older = load(path)
        if snap is None:
            snap = {"collectors": dict(older["collectors"]), "packages": []}
        for name in sorted(todo):
            if name in uses_roots and not same_roots(older["roots"], roots):
                continue
            if older["collectors"].get(name, OK) == OK:
                snap["collectors"][name] = OK
                snap["packages"] += [
                    p for p in older["packages"] if p.ecosystem == name
                ]
                todo.discard(name)
        if not todo:
            break
    for name in todo & set(uses_roots):
        if snap["collectors"].get(name, OK) == OK:
            snap["collectors"][name] = OTHER_ROOTS
    snap["roots"] = roots
    return snap
