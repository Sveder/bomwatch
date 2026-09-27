"""Run external commands without ever raising."""

import shutil
import subprocess

TIMEOUT = 120


def has(tool):
    """Return True when ``tool`` is on the PATH."""
    return shutil.which(tool) is not None


def run(cmd, timeout=TIMEOUT):
    """Return the stdout of ``cmd``, or None if it is missing or fails."""
    if not has(cmd[0]):
        return None
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout
