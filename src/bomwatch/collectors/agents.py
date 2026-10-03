"""What coding agents are allowed to do, and what they are told.

- ``mcp`` (OWASP ASI04, ASI07): every MCP server configured for Claude Code,
  Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI and Codex, user-wide
  and in projects under the roots. The version is a hash of the server's
  command, args and URL (env values are left out). Flags: ``unpinned-launch``,
  ``remote-http`` and the command checks.
- ``agent-config`` (ASI02): Claude Code permission rules, default mode, hooks,
  extra directories and env overrides; Codex approval and sandbox modes.
  Flags: ``broad-shell``, ``bypass-mode``, ``endpoint-override`` and the
  command checks on hook commands.
- ``agent-memory`` (ASI06): instruction, rule, skill, agent and memory files
  (``CLAUDE.md``, ``AGENTS.md``, ``.cursorrules``, ``SKILL.md`` ...). The
  version is a hash of the content. Flags: ``hidden-unicode``,
  ``unicode-tags``, ``injection-phrase`` and the command checks.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from bomwatch import checks, walk
from bomwatch.collectors.common import digest, read_json, read_text, shorten
from bomwatch.model import Package

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 has no TOML reader
    tomllib = None  # pylint: disable=invalid-name

PERMISSION_LISTS = ("allow", "ask", "deny")
MAX_PLUGIN_FILES = 500


def app_dirs(home: Path) -> list[Path]:
    """Return the per-user app config dirs of Linux, macOS and Windows."""
    found = [home / ".config", home / "Library" / "Application Support"]
    if os.environ.get("APPDATA"):
        found.append(Path(os.environ["APPDATA"]))
    return found


# ---------------------------------------------------------------- MCP


def mcp_sources(home: Path, roots) -> list[tuple[Path, str]]:
    """Return ``(config file, key holding the servers)`` for every MCP config."""
    found = [
        (home / ".claude.json", "mcpServers"),
        (home / ".cursor" / "mcp.json", "mcpServers"),
        (home / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers"),
        (home / ".gemini" / "settings.json", "mcpServers"),
    ]
    for base in app_dirs(home):
        found.append((base / "Claude" / "claude_desktop_config.json", "mcpServers"))
        found.append((base / "Code" / "User" / "mcp.json", "servers"))
    for path in walk.find(roots).agent_files:
        if path.name == ".mcp.json" or path.parent.name == ".cursor":
            found.append((path, "mcpServers"))
        elif path.name == "mcp.json" and path.parent.name == ".vscode":
            found.append((path, "servers"))
    return found


def server_record(name, server, location) -> Package | None:
    """Return the record of one MCP server definition."""
    if not isinstance(server, dict):
        return None
    shape = {
        k: server.get(k)
        for k in ("type", "command", "args", "url", "serverUrl", "httpUrl")
        if server.get(k) is not None
    }
    shape["env"] = sorted(server.get("env") or {})
    url = server.get("url") or server.get("serverUrl") or server.get("httpUrl")
    command = " ".join(
        [str(server.get("command") or ""), *map(str, server.get("args") or [])]
    ).strip()
    return Package(
        "mcp",
        str(name),
        digest(json.dumps(shape, sort_keys=True, default=str)),
        location,
        shorten(url or command or "mcp"),
        checks.join(checks.mcp_flags({**server, "url": url})),
    )


def servers_in(servers, location) -> list[Package]:
    """Return the records of a ``{name: definition}`` map."""
    if not isinstance(servers, dict):
        return []
    return [
        r
        for name, server in sorted(servers.items())
        if (r := server_record(name, server, location))
    ]


def codex_servers(path: Path) -> list[Package]:
    """Return the ``[mcp_servers.*]`` of a Codex ``config.toml``."""
    data = codex_config(path)
    return servers_in(data.get("mcp_servers"), str(path)) if data else []


def collect_mcp(roots, home=None):
    """Return every MCP server configured on this machine."""
    home = Path.home() if home is None else Path(home)
    found = []
    seen = set()
    for path, key in mcp_sources(home, roots):
        if path in seen:
            continue
        seen.add(path)
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        found += servers_in(data.get(key), str(path))
        # ~/.claude.json also keeps servers per project.
        for project, conf in sorted((data.get("projects") or {}).items()):
            if isinstance(conf, dict):
                found += servers_in(conf.get("mcpServers"), f"{path}#{project}")
    found += codex_servers(home / ".codex" / "config.toml")
    return found


# ---------------------------------------------------------------- agent config


def codex_config(path: Path) -> dict | None:
    """Return a Codex ``config.toml`` as a dict, or None."""
    text = read_text(path)
    if text is None or tomllib is None:
        return None
    try:
        return tomllib.loads(text)
    except ValueError:
        return None


def config_record(name, value, location, flags=(), source="setting") -> Package:
    """Return one setting record."""
    return Package(
        "agent-config", name, value, str(location), source, checks.join(flags)
    )


def hook_commands(hooks) -> list[tuple[str, str]]:
    """Return ``(event, command)`` for every command hook in a hooks map."""
    found: list[tuple[str, str]] = []
    if not isinstance(hooks, dict):
        return found
    for event, groups in sorted(hooks.items()):
        for group in groups if isinstance(groups, list) else []:
            entries = group.get("hooks", []) if isinstance(group, dict) else []
            for hook in entries if isinstance(entries, list) else []:
                if isinstance(hook, dict) and hook.get("command"):
                    found.append((str(event), str(hook["command"])))
    return found


def hook_records(hooks, location) -> list[Package]:
    """Return one record per hook command; the name holds the command."""
    return [
        config_record(
            f"hook {event}: {shorten(command, 160)}",
            digest(command),
            location,
            checks.command_flags(command),
            "hook",
        )
        for event, command in hook_commands(hooks)
    ]


def claude_settings(path: Path) -> list[Package]:
    """Return the records of one Claude Code ``settings.json``."""
    data = read_json(path)
    if not isinstance(data, dict):
        return []
    found = []
    perms: dict = (
        data["permissions"] if isinstance(data.get("permissions"), dict) else {}
    )
    for kind in PERMISSION_LISTS:
        for rule in perms.get(kind) or []:
            flags = checks.permission_flags(str(rule)) if kind == "allow" else []
            found.append(config_record(f"{kind} {rule}", "", path, flags, "permission"))
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode:
        found.append(
            config_record("defaultMode", str(mode), path, checks.mode_flags(mode))
        )
    for extra in perms.get("additionalDirectories") or []:
        found.append(config_record(f"additionalDirectory {extra}", "", path))
    for key in ("skipDangerousModePermissionPrompt", "dangerouslySkipPermissions"):
        if data.get(key):
            found.append(config_record(key, "true", path, ["bypass-mode"]))
    for name, value in sorted((data.get("env") or {}).items()):
        found.append(
            config_record(
                f"env {name}", digest(str(value)), path, checks.env_flags(name)
            )
        )
    found += hook_records(data.get("hooks"), path)
    return found


def settings_files(home: Path, roots) -> list[Path]:
    """Return the Claude Code settings files: user, managed and per project."""
    found = [
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        Path("/etc/claude-code/managed-settings.json"),
        Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
    ]
    if os.environ.get("ProgramData"):
        found.append(
            Path(os.environ["ProgramData"]) / "ClaudeCode" / "managed-settings.json"
        )
    found += [p for p in walk.find(roots).agent_files if p.parent.name == ".claude"]
    return sorted(set(found))


def plugin_hooks(home: Path) -> list[Package]:
    """Return the hooks that installed Claude Code plugins bring."""
    folder = home / ".claude" / "plugins"
    found: list[Package] = []
    for count, path in enumerate(sorted(folder.rglob("hooks.json"))):
        if count >= MAX_PLUGIN_FILES:
            break
        data = read_json(path)
        if isinstance(data, dict):
            found += hook_records(data.get("hooks", data), path)
    return found


def codex_settings(path: Path) -> list[Package]:
    """Return the approval and sandbox modes of a Codex ``config.toml``."""
    data = codex_config(path) or {}
    return [
        config_record(key, str(data[key]), path, checks.mode_flags(data[key]))
        for key in ("approval_policy", "sandbox_mode")
        if key in data
    ]


def collect_config(roots, home=None):
    """Return the permission and hook settings of the coding agents."""
    home = Path.home() if home is None else Path(home)
    found = []
    for path in settings_files(home, roots):
        found += claude_settings(path)
    return found + plugin_hooks(home) + codex_settings(home / ".codex" / "config.toml")


# ---------------------------------------------------------------- memory


def memory_files(home: Path, roots) -> list[tuple[Path, str]]:
    """Return ``(file, kind)`` for every instruction and memory file."""
    claude = home / ".claude"
    found = [
        (claude / "CLAUDE.md", "instructions"),
        (home / ".codex" / "AGENTS.md", "instructions"),
        (home / ".gemini" / "GEMINI.md", "instructions"),
    ]
    found += [(p, "agent") for p in claude.glob("agents/*.md")]
    found += [(p, "command") for p in claude.glob("commands/**/*.md")]
    found += [(p, "skill") for p in claude.glob("skills/*/SKILL.md")]
    found += [(p, "memory") for p in claude.glob("projects/*/memory/*.md")]
    for count, path in enumerate(sorted((claude / "plugins").rglob("SKILL.md"))):
        if count < MAX_PLUGIN_FILES:
            found.append((path, "plugin-skill"))
    for path in walk.find(roots).agent_files:
        if path.suffix in (".md", ".mdc") or path.name in (
            ".cursorrules",
            ".windsurfrules",
        ):
            found.append((path, kind_of(path)))
    return found


def kind_of(path: Path) -> str:
    """Return what kind of agent file ``path`` is."""
    if path.name == "SKILL.md":
        return "skill"
    if path.parent.name in ("agents", "commands"):
        return path.parent.name[:-1]
    if path.parent.name == "rules" or path.name.startswith("."):
        return "rules"
    return "instructions"


def collect_memory(roots, home=None):
    """Return the instruction, rule, skill and memory files agents read."""
    home = Path.home() if home is None else Path(home)
    found = []
    seen = set()
    for path, kind in memory_files(home, roots):
        if path in seen:
            continue
        seen.add(path)
        text = read_text(path)
        if text is None:
            continue
        name = path.name
        if name == "SKILL.md":
            name = f"{path.parent.name}/SKILL.md"
        found.append(
            Package(
                "agent-memory",
                name,
                digest(text),
                str(path.parent if name == path.name else path.parent.parent),
                kind,
                checks.join(checks.text_flags(text)),
            )
        )
    return found
