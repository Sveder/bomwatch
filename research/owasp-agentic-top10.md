# OWASP Top 10 for Agentic Applications: what a host tool can check

bomwatch started as "what got installed on this machine". It works by
reading machine state, saving a snapshot, and diffing snapshots. This note
looks at which of the
[OWASP Top 10 for Agentic Applications](https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026)
(published December 2025, ASI01–ASI10) can be handled the same way, on the
machine where an agent runs.

Each risk gets one of three answers:

- **Report:** read state from disk, diff it against the last scan, and flag
  what looks dangerous. This is the bomwatch model, and it works after the
  fact whatever path the change took.
- **Prevent:** stop the action before it happens: an agent hook, a wrapper,
  a sandbox, an egress policy.
- **Out of reach:** a host tool can't decide it reliably.

## Summary

| # | Risk | Report (bomwatch-style) | Prevent | Fit |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | Only heuristics on content the agent reads | No reliable control; limit blast radius instead | Weak |
| ASI02 | Tool Misuse & Exploitation | Agent permission config, hooks; destructive commands in transcripts | Pre-tool-use hook with a deny policy | Strong |
| ASI03 | Identity & Privilege Abuse | SSH keys, token stores, sudoers, login users | Separate OS user, short-lived scoped tokens | Strong |
| ASI04 | Agentic Supply Chain | **Done:** packages, apps, OSV. Next: MCP servers, skills, plugins | Install wrappers, minimum release age, allowlists | Strong |
| ASI05 | Unexpected Code Execution | Autostart: cron, systemd, launchd, Run keys, scheduled tasks, shell rc files | Sandbox; hook denies writes to autostart paths | Strong |
| ASI06 | Memory & Context Poisoning | Instruction and memory files: diff plus hidden-Unicode and injection checks | Read-only instruction files, reviewed memory writes | Good (detection is heuristic) |
| ASI07 | Insecure Inter-Agent Communication | MCP configs over plain `http://`, servers listening on all interfaces | Local-only, authenticated transports | Medium |
| ASI08 | Cascading Failures | Rates: commits and pushes per hour, processes, disk, spend | Resource and budget caps | Medium |
| ASI09 | Human-Agent Trust Exploitation | Diff what the agent *says* it did against what the scans saw | — | Low, but cheap |
| ASI10 | Rogue Agents | New outbound domains, agent processes outside their schedule | Egress allowlist proxy | Good, needs a network part |

## Per risk

### ASI01: Agent Goal Hijack

Prompt injection through a web page, an issue or a file redirects the agent.
Whether text is an attack depends on its meaning, so a filesystem scan can't
decide it. Pattern matching ("ignore previous instructions") is easy to get
around. **Approach:** don't try to detect it directly. The other rows limit
what a hijacked agent can do and record what it did. ASI06 checks cover the
part that persists on disk.

### ASI02: Tool Misuse & Exploitation

The agent uses legitimate tools destructively, or with more reach than
intended.

- **Report:** collect agent permission configs (Claude Code
  `settings.json`, `.claude/settings.local.json`, MCP lists, hooks) as
  records, so the diff shows `+ allow Bash(*)` or a mode switched to bypass.
  Flag broad rules. Later: scan agent transcripts for `rm -rf`,
  `git push --force`, `DROP TABLE`.
- **Prevent:** a `PreToolUse` hook that checks commands against a policy.

### ASI03: Identity & Privilege Abuse

The agent uses, leaks or adds credentials, or raises its privileges.

- **Report:** `~/.ssh/authorized_keys` entries (by fingerprint), private
  keys (flag unencrypted ones), token stores (`.npmrc`, `.pypirc`,
  `gh/hosts.yml`, `.aws/credentials`, `.docker/config.json`, `.netrc`,
  `.git-credentials`, kube contexts), `sudoers` and `sudoers.d`, login users.
  Store only names and a truncated hash of the secret, so a new or rotated
  token shows as a change and the value never lands in a snapshot.
- **Prevent:** run the agent as its own OS user with scoped, short-lived
  tokens.

### ASI04: Agentic Supply Chain Vulnerabilities

Malicious or vulnerable packages, tools, MCP servers, plugins and skills.

- **Done:** 20 package and app collectors, OSV lookups, SBOM export.
- **Next:** MCP servers as records (name, command or URL, config hash).
  Flag unpinned `npx -y` / `uvx` launches. Later: package age (published in
  the last N days) and names close to popular packages.
- **Prevent:** install wrappers or a hook; `uv`'s `exclude-newer` and
  minimum-release-age settings in package managers.

### ASI05: Unexpected Code Execution

The agent runs code, or sets it up to run later.

- **Report:** everything that starts code later: user and system crontabs,
  systemd units and timers, macOS LaunchAgents and LaunchDaemons, Windows Run
  and RunOnce keys, Startup folders, scheduled tasks, shell startup files
  (`.bashrc`, `.zshrc`, `.profile`, PowerShell profiles). Flag entries that
  pipe downloads into a shell, decode base64, or run from `/tmp` or
  Downloads.
- **Prevent:** a sandbox or container; a hook that denies writes to those
  paths.

### ASI06: Memory & Context Poisoning

Instructions the agent reads every session (`CLAUDE.md`, `AGENTS.md`,
`.cursorrules`, rules, skills, memory files) get altered to steer later runs.

- **Report:** each file as a record with a content hash, so any edit shows up
  in the diff. Flag invisible or bidirectional Unicode, Unicode tag
  characters, and injection phrasing. Include files that arrive with freshly
  cloned repos under the roots.
- **Prevent:** make the files read-only to the agent; review memory writes.

### ASI07: Insecure Inter-Agent Communication

- **Report:** MCP servers reached over plain `http://` on a non-local host.
  Later: agent processes listening on `0.0.0.0`.
- **Prevent:** local-only or authenticated transports.

### ASI08: Cascading Failures

A loop or chain of agents amplifies one mistake.

- **Report:** rate signals, such as commits and pushes per hour, process
  count, disk growth and API spend, with alerts on spikes.
- **Prevent:** resource limits, tool-call caps, budget caps.

### ASI09: Human-Agent Trust Exploitation

The agent misleads the human, on purpose or not. A host tool can provide
ground truth: compare the agent's end-of-run summary with the bomwatch diff
for the same window.

### ASI10: Rogue Agents

The agent acts outside its mandate or drifts over time.

- **Report:** domains contacted for the first time (DNS log or proxy log);
  agent processes running outside their schedule.
- **Prevent:** an egress allowlist through a proxy. This is the most
  effective single control on this list.

## Plan

1. **Autostart and credentials (ASI05, ASI03).** Collectors `autostart`
   and `credential`. *Done.*
2. **Agent config and memory (ASI02, ASI06, the MCP part of ASI04, ASI07).**
   Collectors `mcp`, `agent-config`, `agent-memory`. *Done.*
3. A `PreToolUse` policy hook to block what 1 and 2 report.
4. Outbound domain log.

Not covered yet from 1 and 2: git hooks in repos, setuid binaries,
listening ports, Cursor permissions (kept in a SQLite database), and
package age and typosquat checks.

Records from 1 and 2 carry **flags**, short names for what looks dangerous
(`pipe-to-shell`, `remote-http`, `hidden-unicode` ...). `bomwatch diff`
shows the flags next to each new record and exits 4 when a new record is
flagged. `bomwatch audit` lists every flagged record in a scan.

## Sources

- [Giskard: OWASP Top 10 for Agentic Applications 2026](https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026)
- [Cycode: OWASP Top 10 for Agentic Applications](https://cycode.com/blog/owasp-top-10-agentic-applications/)
- [Modulos: OWASP Top 10 Agentic](https://docs.modulos.ai/frameworks/owasp-top-10-agentic)
