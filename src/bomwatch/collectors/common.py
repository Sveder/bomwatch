"""Small helpers shared by the collectors that read config files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

MAX_READ = 1024 * 1024


def digest(data: str | bytes) -> str:
    """Return a short, stable hash of ``data``: a version for content records."""
    raw = data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()[:12]


def read_text(path) -> str | None:
    """Return up to 1 MiB of text from ``path``, or None if it can't be read."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(MAX_READ)
    except OSError:
        return None


def read_json(path):
    """Return the parsed JSON at ``path``, or None."""
    text = read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def files_in(folder, suffixes=None) -> list[Path]:
    """Return the regular files directly in ``folder`` (symlinks followed), sorted."""
    try:
        entries = sorted(Path(folder).iterdir())
    except OSError:
        return []
    return [
        e for e in entries if e.is_file() and (suffixes is None or e.suffix in suffixes)
    ]


def shorten(text: str, limit: int = 300) -> str:
    """Return ``text`` on one line, cut to ``limit`` characters."""
    line = " ".join(str(text).split())
    return line if len(line) <= limit else line[: limit - 1] + "…"
