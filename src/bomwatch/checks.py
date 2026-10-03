"""Risk heuristics for the records that are not packages.

Each function returns a sorted list of flag names. A flag says "a person
should look at this", not "this is malicious": the checks are patterns, and
they can be both evaded and wrong.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------- commands

COMMAND_PATTERNS = {
    "pipe-to-shell": re.compile(
        r"\b(curl|wget|iwr|invoke-webrequest)\b[^|\n]*\|\s*(sudo\s+)?"
        r"(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?python",
        re.IGNORECASE,
    ),
    "download-exec": re.compile(
        r"\b(iex|invoke-expression)\b|downloadstring\(|downloadfile\(|"
        r"\bbash\s+<\(\s*(curl|wget)\b|\bsh\s+-c\s+[\"']?\$\(\s*(curl|wget)\b",
        re.IGNORECASE,
    ),
    "encoded-command": re.compile(
        r"base64\s+(-d|--decode)\b|frombase64string|"
        r"\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}",
        re.IGNORECASE,
    ),
    "reverse-shell": re.compile(
        r"/dev/tcp/|\bnc(at)?\b[^\n]*\s-e\s|\bbash\s+-i\s+>&|\bsocat\b[^\n]*exec:",
        re.IGNORECASE,
    ),
    "temp-path": re.compile(
        r"(^|[\s\"'=:])(/tmp/|/var/tmp/|/dev/shm/)|\\appdata\\local\\temp\\|"
        r"%temp%|[/\\]downloads[/\\]",
        re.IGNORECASE,
    ),
}


def command_flags(text: str) -> list[str]:
    """Return the risk flags of a command line or a script."""
    return sorted(name for name, rx in COMMAND_PATTERNS.items() if rx.search(text))


# ---------------------------------------------------------------- text

HIDDEN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
TAGS = re.compile(r"[\U000e0000-\U000e007f]")
INJECTION = re.compile(
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+"
    r"(instructions|rules|messages)|"
    r"disregard\s+(all\s+|any\s+)?(previous|prior|above|your)\s+(instructions|rules)|"
    r"do\s+not\s+(tell|inform|mention\s+(this\s+)?to)\s+the\s+user|"
    r"without\s+(telling|informing|asking)\s+the\s+user|"
    r"(send|upload|post|exfiltrate)\s+[^\n]{0,40}?"
    r"(secrets?|tokens?|credentials|api[_ ]?keys?|\.env|id_rsa|ssh\s+keys?)",
    re.IGNORECASE,
)


def text_flags(text: str) -> list[str]:
    """Return the risk flags of an instruction or memory file.

    A byte order mark at the very start is normal and is not flagged.
    """
    found = set(command_flags(text))
    if HIDDEN.search(text.removeprefix("\ufeff")):
        found.add("hidden-unicode")
    if TAGS.search(text):
        found.add("unicode-tags")
    if INJECTION.search(text):
        found.add("injection-phrase")
    return sorted(found)


# ---------------------------------------------------------------- agents

BROAD_RULES = re.compile(r"^(Bash|PowerShell)(\((\*|:\*|\*:\*)?\))?$")
BYPASS_MODES = {"bypassPermissions", "never", "danger-full-access", "yolo"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}  # noqa: S104


def permission_flags(rule: str) -> list[str]:
    """Return ``["broad-shell"]`` for an allow rule that permits any command."""
    return ["broad-shell"] if BROAD_RULES.match(rule.strip()) else []


def mode_flags(value: str) -> list[str]:
    """Return ``["bypass-mode"]`` for a mode that skips approval or the sandbox."""
    return ["bypass-mode"] if str(value) in BYPASS_MODES else []


def unpinned(args: list[str]) -> bool:
    """Return True when an ``npx``/``uvx``/``pipx run`` launch has no fixed version."""
    names = [a for a in args if not a.startswith("-")]
    if not names:
        return False
    package = names[0]
    if package.endswith("@latest"):
        return True
    if package.startswith("@"):
        return "@" not in package[1:]
    return "@" not in package and "==" not in package


def mcp_flags(server: dict) -> list[str]:
    """Return the risk flags of one MCP server definition."""
    found = set()
    url = str(server.get("url") or server.get("serverUrl") or "")
    if url:
        parsed = urlparse(url)
        if parsed.scheme == "http" and (parsed.hostname or "") not in LOCAL_HOSTS:
            found.add("remote-http")
    command = str(server.get("command") or "")
    args = [str(a) for a in server.get("args") or [] if isinstance(a, (str, int))]
    launcher = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    launcher = launcher.removesuffix(".cmd").removesuffix(".exe")
    if launcher in ("npx", "bunx", "uvx") and unpinned(args):
        found.add("unpinned-launch")
    if launcher in ("pipx", "uv") and args[:1] in (["run"], ["tool"]):
        if unpinned(args[1:] if args[0] == "run" else args[2:]):
            found.add("unpinned-launch")
    found.update(command_flags(" ".join([command, *args])))
    return sorted(found)


def env_flags(name: str) -> list[str]:
    """Return ``["endpoint-override"]`` for an env var that redirects API traffic."""
    upper = name.upper()
    if upper.endswith(("_BASE_URL", "_API_URL", "_ENDPOINT")) or upper in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        return ["endpoint-override"]
    return []


def join(*groups) -> str:
    """Return the flag lists in ``groups`` as one sorted, comma separated string."""
    return ",".join(sorted({flag for group in groups for flag in group}))
