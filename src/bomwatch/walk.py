"""One walk over the roots, shared by every collector that searches them.

The walk finds Python envs (``pyvenv.cfg`` or ``conda-meta/``), Node
projects (a ``package.json`` next to ``node_modules/``) and the files coding
agents read: instructions, rules, skills, settings and MCP configs. The
result is cached per set of roots until ``clear()``, so the collectors walk
the disk once.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", ".cache", "__pycache__", "proc", "sys"}
MAX_DEPTH = 6
log = logging.getLogger(__name__)
AGENT_NAMES = {
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".mcp.json",
}
# Inside these dirs only the listed subdirs hold agent files; the rest (such
# as ~/.claude/projects with its transcripts) is not walked.
AGENT_DIRS = {
    ".claude": {"agents", "commands", "skills"},
    ".cursor": {"rules"},
}


def is_agent_file(folder: Path, name: str) -> bool:
    """Return True for a file a coding agent reads as instructions or config."""
    parent, grand = folder.name, folder.parent.name
    if name in AGENT_NAMES:
        return True
    if parent == ".claude":
        return name in ("settings.json", "settings.local.json")
    if parent in (".cursor", ".vscode"):
        return name == "mcp.json"
    if parent == ".github":
        return name == "copilot-instructions.md"
    if parent == "rules" and grand == ".cursor":
        return name.endswith((".mdc", ".md"))
    if parent in ("agents", "commands") and grand == ".claude":
        return name.endswith(".md")
    return name == "SKILL.md" and grand == "skills"


@dataclass(frozen=True)
class Found:
    """What one walk found."""

    envs: tuple[Path, ...]
    projects: tuple[Path, ...]
    unreadable: int
    agent_files: tuple[Path, ...] = ()


def _walk(roots: tuple[Path, ...], max_depth: int) -> Found:
    envs, projects, errors = set(), set(), []
    agent_files: set[Path] = set()

    def unreadable(error: OSError) -> None:
        errors.append(error)
        log.debug("cannot read %s: %s", error.filename, error.strerror)

    for root in roots:
        base_depth = len(root.parts)
        for current, dirs, files in os.walk(root, onerror=unreadable):
            here = Path(current)
            if "pyvenv.cfg" in files:
                envs.add(here)
                dirs[:] = []
                continue
            if "conda-meta" in dirs:
                envs.add(here)
                dirs[:] = [d for d in dirs if d == "envs"]
                continue
            if "package.json" in files and "node_modules" in dirs:
                projects.add(here)
            agent_files.update(here / f for f in files if is_agent_file(here, f))
            depth = len(here.parts) - base_depth
            keep = AGENT_DIRS.get(here.name)
            dirs[:] = [
                d
                for d in dirs
                if d not in SKIP_DIRS
                and depth < max_depth
                and (keep is None or d in keep)
            ]
    if errors:
        log.info("%d directories under the roots could not be read", len(errors))
    return Found(
        tuple(sorted(envs)),
        tuple(sorted(projects)),
        len(errors),
        tuple(sorted(agent_files)),
    )


@lru_cache(maxsize=8)
def _cached(roots: tuple[Path, ...], max_depth: int) -> Found:
    return _walk(roots, max_depth)


def find(roots, max_depth: int = MAX_DEPTH) -> Found:
    """Return the envs and projects under ``roots`` (cached, see ``clear``)."""
    return _cached(tuple(sorted(Path(r) for r in roots)), max_depth)


def clear() -> None:
    """Forget cached walks, so the next scan sees the disk as it is now."""
    _cached.cache_clear()
