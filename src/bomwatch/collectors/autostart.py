"""Everything that starts code later without anyone asking (OWASP ASI05).

An agent that wants code to outlive its session writes it to one of these
places. Each entry is a record; files are versioned by a hash of their
content, so any edit shows up as a change, and the risk checks in
``bomwatch.checks`` add flags such as ``pipe-to-shell``.

- cron: the user crontab, ``/etc/crontab``, ``/etc/cron.d``, one record per
  line; scripts in ``/etc/cron.{hourly,daily,weekly,monthly}``.
- systemd: unit files of the user and the system.
- launchd: LaunchAgents and LaunchDaemons (macOS).
- shell startup files: ``.bashrc``, ``.zshrc``, ``.profile``, fish and
  PowerShell profiles.
- Windows: Run and RunOnce keys, the Startup folders and scheduled tasks
  outside ``\\Microsoft\\``.
"""

from __future__ import annotations

import json
import os
import plistlib
import sys
from pathlib import Path

from bomwatch import checks
from bomwatch.collectors.common import digest, files_in, read_text, shorten
from bomwatch.model import Package
from bomwatch.runner import has, run

ECO = "autostart"
SHELL_FILES = (
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".config/fish/config.fish",
    ".config/powershell/Microsoft.PowerShell_profile.ps1",
    "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
    "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
)
UNIT_SUFFIXES = {".service", ".timer", ".socket", ".path"}
CRON_DIRS = ("cron.hourly", "cron.daily", "cron.weekly", "cron.monthly")
RUN_KEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)
TASK_SCRIPT = (
    "Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } |"
    " ForEach-Object { [pscustomobject]@{ Path = $_.TaskPath + $_.TaskName;"
    ' Run = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" })'
    " -join '; ') } } | ConvertTo-Json -Compress"
)


def file_record(path: Path, source: str, text: str | None = None) -> Package | None:
    """Return a record for one file, versioned by its content hash."""
    text = read_text(path) if text is None else text
    if text is None:
        return None
    return Package(
        ECO,
        path.name,
        digest(text),
        str(path.parent),
        source,
        checks.join(checks.command_flags(text)),
    )


# ---------------------------------------------------------------- cron


def cron_lines(text: str, location: str) -> list[Package]:
    """Return one record per job line of a crontab; comments and env lines skipped."""
    found = []
    for raw in text.splitlines():
        line = " ".join(raw.split())
        if not line or line.startswith("#"):
            continue
        head = line.split(" ", 1)[0]
        if "=" in head and not head.startswith(("@", "*")) and not head[0].isdigit():
            continue
        found.append(
            Package(
                ECO,
                shorten(line, 200),
                "",
                location,
                "cron",
                checks.join(checks.command_flags(line)),
            )
        )
    return found


def collect_cron(etc: Path = Path("/etc")) -> list[Package]:
    """Return the user crontab and the system cron jobs."""
    found = []
    if has("crontab"):
        # ``crontab -l`` fails when the user has no crontab: that is "none".
        found += cron_lines(run(["crontab", "-l"]) or "", "crontab -l")
    for path in [etc / "crontab", *files_in(etc / "cron.d")]:
        text = read_text(path)
        if text is not None:
            found += cron_lines(text, str(path))
    for name in CRON_DIRS:
        found += [
            r for p in files_in(etc / name) if (r := file_record(p, "cron-script"))
        ]
    return found


# ---------------------------------------------------------------- systemd, launchd


def unit_dirs(home: Path, etc: Path) -> list[Path]:
    """Return the systemd dirs where units are installed by users and admins."""
    return [
        home / ".config" / "systemd" / "user",
        etc / "systemd" / "system",
        etc / "systemd" / "user",
    ]


def collect_systemd(home: Path, etc: Path = Path("/etc")) -> list[Package]:
    """Return systemd unit files; only ``Exec*`` lines are checked for risks."""
    found = []
    for folder in unit_dirs(home, etc):
        for path in files_in(folder, UNIT_SUFFIXES):
            text = read_text(path)
            if text is None:
                continue
            execs = "\n".join(
                line for line in text.splitlines() if line.strip().startswith("Exec")
            )
            found.append(
                Package(
                    ECO,
                    path.name,
                    digest(text),
                    str(folder),
                    "systemd",
                    checks.join(checks.command_flags(execs)),
                )
            )
    return found


def launchd_dirs(home: Path) -> list[Path]:
    """Return the LaunchAgents and LaunchDaemons dirs."""
    return [
        home / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]


def plist_command(path: Path) -> tuple[bytes, str] | None:
    """Return ``(raw bytes, command line)`` of a launchd plist, or None."""
    try:
        raw = path.read_bytes()
        data = plistlib.loads(raw)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    if not isinstance(data, dict):
        return raw, ""
    args = data.get("ProgramArguments") or [data.get("Program") or ""]
    return raw, " ".join(str(a) for a in args if a)


def collect_launchd(home: Path, dirs=None) -> list[Package]:
    """Return launchd jobs (macOS)."""
    found = []
    for folder in launchd_dirs(home) if dirs is None else dirs:
        for path in files_in(folder, {".plist"}):
            parsed = plist_command(path)
            if parsed is None:
                continue
            raw, command = parsed
            found.append(
                Package(
                    ECO,
                    path.stem,
                    digest(raw),
                    str(folder),
                    shorten(command) or "launchd",
                    checks.join(checks.command_flags(command)),
                )
            )
    return found


def collect_shell(home: Path) -> list[Package]:
    """Return the shell and PowerShell startup files of the user."""
    found = []
    for name in SHELL_FILES:
        path = home / name
        if path.is_file() and (record := file_record(path, "shell-startup")):
            found.append(record)
    return found


# ---------------------------------------------------------------- Windows


def run_key_values(reg) -> list[Package]:
    """Return the Run and RunOnce entries of the user and the machine."""
    found = []
    views = [
        ("HKCU", reg.HKEY_CURRENT_USER, reg.KEY_READ),
        (
            "HKLM",
            reg.HKEY_LOCAL_MACHINE,
            reg.KEY_READ | getattr(reg, "KEY_WOW64_64KEY", 0),
        ),
        (
            "HKLM32",
            reg.HKEY_LOCAL_MACHINE,
            reg.KEY_READ | getattr(reg, "KEY_WOW64_32KEY", 0),
        ),
    ]
    for label, hive, access in views:
        for path in RUN_KEYS:
            try:
                key = reg.OpenKey(hive, path, 0, access)
            except OSError:
                continue
            with key:
                index = 0
                while True:
                    try:
                        name, value, _ = reg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    command = str(value)
                    found.append(
                        Package(
                            ECO,
                            str(name),
                            digest(command),
                            f"{label}\\{path}",
                            shorten(command),
                            checks.join(checks.command_flags(command)),
                        )
                    )
    return found


def startup_folders() -> list[Path]:
    """Return the per-user and all-users Startup folders."""
    tail = Path("Microsoft", "Windows", "Start Menu", "Programs")
    found = []
    if os.environ.get("APPDATA"):
        found.append(Path(os.environ["APPDATA"]) / tail / "Startup")
    if os.environ.get("ProgramData"):
        found.append(Path(os.environ["ProgramData"]) / tail / "StartUp")
    return found


def collect_startup_folders(folders=None) -> list[Package]:
    """Return the files in the Startup folders."""
    found = []
    for folder in startup_folders() if folders is None else folders:
        for path in files_in(folder):
            try:
                raw = path.read_bytes()[:1_000_000]
            except OSError:
                continue
            text = raw.decode("utf-8", "replace")
            found.append(
                Package(
                    ECO,
                    path.name,
                    digest(raw),
                    str(folder),
                    "startup-folder",
                    checks.join(checks.command_flags(text)),
                )
            )
    return found


def parse_tasks(output: str) -> list[Package] | None:
    """Turn the JSON of the scheduled task script into records."""
    if not output.strip():
        return []
    try:
        data = json.loads(output)
    except ValueError:
        return None
    if isinstance(data, dict):
        data = [data]
    found = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict) or not item.get("Path"):
            continue
        command = str(item.get("Run") or "")
        found.append(
            Package(
                ECO,
                str(item["Path"]),
                digest(command),
                "scheduled-tasks",
                shorten(command),
                checks.join(checks.command_flags(command)),
            )
        )
    return found


def collect_windows(reg=None) -> list[Package] | None:
    """Return the Windows autostart entries; [] on other systems."""
    if reg is None:
        if sys.platform != "win32":
            return []
        import winreg as reg  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,import-error
    found = run_key_values(reg) + collect_startup_folders()
    if has("powershell"):
        output = run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", TASK_SCRIPT]
        )
        tasks = None if output is None else parse_tasks(output)
        if tasks is None:
            return None
        found += tasks
    return found


def collect(_roots, home=None):
    """Return every autostart entry of this machine."""
    home = Path.home() if home is None else Path(home)
    windows = collect_windows()
    if windows is None:
        return None
    return (
        collect_cron()
        + collect_systemd(home)
        + collect_launchd(home)
        + collect_shell(home)
        + windows
    )
