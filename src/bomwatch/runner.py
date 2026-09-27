"""Run external commands without ever raising."""

from __future__ import annotations

import logging
import shutil
import subprocess

TIMEOUT = 120
log = logging.getLogger(__name__)


def has(tool: str) -> bool:
    """Return True when ``tool`` is on the PATH."""
    return shutil.which(tool) is not None


def run(cmd: list[str], timeout: int = TIMEOUT) -> str | None:
    """Return the stdout of ``cmd``, or None if it is missing or fails.

    The tool is resolved on the PATH first, so ``npm`` finds ``npm.cmd`` on
    Windows too.
    """
    path = shutil.which(cmd[0])
    if path is None:
        return None
    try:
        result = subprocess.run(
            [path, *cmd[1:]],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.info("%s: %s", cmd[0], exc)
        return None
    if result.returncode != 0:
        log.info(
            "%s exited %d: %s",
            " ".join(cmd),
            result.returncode,
            (result.stderr or "").strip()[:500],
        )
        return None
    return result.stdout
