"""Save and load scans as timestamped JSON files."""

from __future__ import annotations

import errno
import json
import logging
import os
import platform
import socket
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from bomwatch.model import OK, Package

SCHEMA = 5
OTHER_ROOTS = "other roots"
NOT_RUN = "not run"
IS_WINDOWS = os.name == "nt"
log = logging.getLogger(__name__)


def state_dir(path=None) -> Path:
    """Return the state dir: ``path``, then $BOMWATCH_STATE_DIR, then the default.

    The default is ``~/.local/state/bomwatch``, or ``%LOCALAPPDATA%\\bomwatch``
    on Windows.
    """
    if path:
        return Path(path)
    if os.environ.get("BOMWATCH_STATE_DIR"):
        return Path(os.environ["BOMWATCH_STATE_DIR"])
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "bomwatch"
    return Path.home() / ".local" / "state" / "bomwatch"


def snapshot_dir(base) -> Path:
    """Return the directory that holds the scan files."""
    return Path(base) / "snapshots"


def os_info() -> dict:
    """Return the OS name and, on Linux, the os-release id and version."""
    info = {"system": platform.system(), "release": platform.release()}
    try:
        release = platform.freedesktop_os_release()
    except (OSError, AttributeError):
        return info
    for key in ("ID", "VERSION_ID", "VERSION_CODENAME", "VERSION"):
        if release.get(key):
            info[key.lower()] = release[key]
    return info


def make(packages, collector_status=None, roots=None, now=None, host=None, system=None):
    """Return a snapshot dict for ``packages``, the ``{collector: status}`` map
    and the searched ``roots``."""
    now = now or datetime.now(timezone.utc)
    return {
        "schema": SCHEMA,
        "collectors": dict(sorted((collector_status or {}).items())),
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host or socket.gethostname(),
        "os": system if system is not None else os_info(),
        "packages": [p.to_dict() for p in sorted(packages)],
        "roots": sorted(str(r) for r in roots) if roots is not None else None,
    }


def _place(tmp: Path, path: Path) -> bool:
    """Move ``tmp`` to ``path`` unless ``path`` exists; return False if it does.

    POSIX ``rename`` would overwrite, so a hard link claims the name instead;
    Windows ``rename`` already refuses an existing target.
    """
    try:
        if IS_WINDOWS:
            os.rename(tmp, path)
            return True
        os.link(tmp, path)
    except FileExistsError:
        return False
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.ENOTSUP, errno.EXDEV, errno.EMLINK):
            raise
        # No hard links on this file system: claim the name, then replace it.
        try:
            with open(path, "x", encoding="utf-8"):
                pass
        except FileExistsError:
            return False
        os.replace(tmp, path)
        return True
    os.unlink(tmp)
    return True


def save(snap, base) -> Path:
    """Write ``snap`` into the state dir and return the file path.

    The file is written to a temporary name, flushed to disk and then moved
    into place, so a crash never leaves a half written scan. Two scans in the
    same second get ``-1``, ``-2`` ... suffixes, even when they run at once.
    """
    folder = snapshot_dir(base)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = snap["created"].replace("-", "").replace(":", "")
    handle, name = tempfile.mkstemp(prefix=".tmp-scan-", suffix=".json", dir=folder)
    tmp = Path(name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(json.dumps(snap, sort_keys=True, indent=1) + "\n")
            out.flush()
            os.fsync(out.fileno())
        count = 0
        while True:
            suffix = f"-{count}" if count else ""
            path = folder / f"scan-{stamp}{suffix}.json"
            if _place(tmp, path):
                return path
            count += 1
    finally:
        if tmp.exists():
            tmp.unlink()


def load(path):
    """Read a snapshot file and return it with ``Package`` records.

    Schema 1 files hold no collector status; every collector counts as ok.
    Files before schema 3 hold no roots (``None``, unknown).
    Raises ValueError when the file is not a bomwatch snapshot, or comes from
    a newer bomwatch.
    """
    try:
        snap = json.loads(Path(path).read_text(encoding="utf-8"))
        schema = int(snap.get("schema", 1))
        snap["packages"] = [Package(**p) for p in snap["packages"]]
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"not a bomwatch snapshot: {path}") from exc
    if schema > SCHEMA:
        raise ValueError(
            f"{path} has schema {schema}, this bomwatch reads up to {SCHEMA};"
            " upgrade bomwatch"
        )
    snap["schema"] = schema
    snap.setdefault("collectors", {})
    snap.setdefault("roots", None)
    snap.setdefault("os", {})
    return snap


def try_load(path):
    """Return ``load(path)``, or None with a warning when the file is unreadable."""
    try:
        return load(path)
    except (OSError, ValueError) as exc:
        print(f"bomwatch: skipping {path}: {exc}", file=sys.stderr)
        return None


def status(snap, name) -> str:
    """Return the status of collector ``name`` in ``snap``.

    Schema 1 files hold no status, so every collector counts as ok. In newer
    files a collector that is missing did not exist yet: ``NOT_RUN``.
    """
    if snap.get("schema", SCHEMA) < 2:
        return snap["collectors"].get(name, OK)
    return snap["collectors"].get(name, NOT_RUN)


def history(base):
    """Return the saved scan files, oldest first."""
    return sorted(snapshot_dir(base).glob("scan-*.json"), key=scan_order)


def scan_order(path):
    """Sort key for a scan file: its time stamp, then its same-second counter."""
    stamp, _, count = path.stem.partition("Z")
    count = count.lstrip("-")
    return stamp, int(count) if count.isdigit() else 0


def latest(files):
    """Return ``(index, snapshot)`` of the newest readable file, or None."""
    for index in range(len(files) - 1, -1, -1):
        snap = try_load(files[index])
        if snap is not None:
            return index, snap
    return None


def same_roots(one, other):
    """Return True unless both root lists are known and differ."""
    return one is None or other is None or one == other


def baseline(files, wanted, roots=None, uses_roots=()):
    """Return the snapshot to diff against, built from ``files`` (oldest first).

    Each collector in ``wanted`` takes its packages from the newest file where it
    was ok, so a change made while it was skipped or failed is still reported.
    A collector in ``uses_roots`` only takes a file scanned with the same ``roots``;
    when no such file exists its status is ``OTHER_ROOTS``.
    Other collectors keep the status of the newest file. Unreadable files are
    skipped with a warning. Returns None when no file is readable.
    """
    snap, todo = None, set(wanted)
    for path in reversed(files):
        older = try_load(path)
        if older is None:
            continue
        if snap is None:
            snap = {
                "schema": SCHEMA,
                "collectors": {n: status(older, n) for n in set(wanted)},
                "os": older["os"],
                "packages": [],
            }
            snap["collectors"].update(older["collectors"])
        for name in sorted(todo):
            if name in uses_roots and not same_roots(older["roots"], roots):
                continue
            if status(older, name) == OK:
                snap["collectors"][name] = OK
                snap["packages"] += [
                    p for p in older["packages"] if p.ecosystem == name
                ]
                todo.discard(name)
        if not todo:
            break
    if snap is None:
        return None
    for name in todo & set(uses_roots):
        if snap["collectors"].get(name) == OK:
            snap["collectors"][name] = OTHER_ROOTS
    snap["roots"] = roots
    return snap


def prune(base, keep):
    """Delete all but the newest ``keep`` scan files; return the deleted paths."""
    files = history(base)
    doomed = files[: max(len(files) - keep, 0)]
    for path in doomed:
        path.unlink()
    return doomed
