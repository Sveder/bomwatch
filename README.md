# bomwatch

A software bill of materials (SBOM) for the machine it runs on, and an alert
when new software appears. Built for machines where AI agents install packages
on their own.

bomwatch lists what is installed on a Linux, macOS or Windows machine, from
system packages and language packages to Steam games and programs dropped in
`~/Downloads`. It saves each scan and tells you what changed since the last
one. It can export the list as CycloneDX or SPDX, and look up known
vulnerabilities on [osv.dev](https://osv.dev).

Status: early work. Not released yet. Site: <https://sveder.github.io/bomwatch/>

## Install

```sh
git clone https://github.com/Sveder/bomwatch.git
cd bomwatch
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e '.[dev]'       # or: make install
bomwatch --version
```

Python 3.10 or newer. No other dependencies at run time.

## Quick start

```sh
bomwatch scan          # list installed software, save a snapshot
# ... install something ...
bomwatch scan
bomwatch diff          # what changed since the scan before
bomwatch diff --vulns  # ... and do the new versions have known vulnerabilities?
```

A full scan of a server with 2437 packages takes about 0.9 s.

## Commands

```sh
bomwatch scan                          # all collectors, save a snapshot
bomwatch scan --only dpkg,pip          # some collectors only
bomwatch scan --root /srv --root ~     # where to look for envs and projects
bomwatch scan --json --no-save         # counts as JSON, nothing written
bomwatch diff                          # last scan against the ones before
bomwatch diff OLD.json NEW.json --json # two named snapshots
bomwatch diff --vulns                  # look up new versions on osv.dev
bomwatch export --format cyclonedx     # newest scan as CycloneDX 1.5 JSON
bomwatch export FILE --format spdx -o sbom.spdx.json
bomwatch vulns                         # every package of the newest scan on osv.dev
bomwatch log jinja2                    # when a package appeared and changed
bomwatch watch --interval 300          # scan every 5 minutes, print changes
bomwatch prune --keep 100              # delete old snapshots
```

Every command takes `--state-dir` and `-v` (`-vv` for debug output, such as
directories that could not be read).

## Collectors

| collector | what | platform |
|---|---|---|
| `dpkg` | Debian and Ubuntu packages, with their source package | Linux |
| `rpm` | RPM packages (Fedora, RHEL, SUSE ...) | Linux |
| `snap`, `flatpak` | snaps; flatpak apps and runtimes | Linux |
| `brew` | Homebrew formulae and casks, read from the Cellar | macOS, Linux |
| `pip` | the system Python, user-site, and every venv or conda env under the roots (pipx and uv tools too) | all |
| `npm` | global packages of `npm root -g`, nvm and nvm-windows | all |
| `npm-project` | top-level `node_modules` of every Node project under the roots | all |
| `cargo` | `cargo install` crates | all |
| `go` | `go install` binaries, read with `go version -m` | all |
| `docker`, `podman` | container images; a new `latest` shows as `~` changed | all |
| `vscode` | VS Code, Cursor, Windsurf and VSCodium extensions | all |
| `steam` | games and tools installed through Steam, in every library | all |
| `portable` | `.exe`, AppImage and ELF programs in Downloads, Desktop, `~/bin`, `~/.local/bin`, `%LOCALAPPDATA%\Programs` and winget's portable folder | all |
| `macapp` | `.app` bundles in `/Applications` and `~/Applications` | macOS |
| `windows` | the Windows "Installed apps" list (Uninstall registry keys; installers, MSI and winget) | Windows |
| `appx` | Microsoft Store and MSIX packages | Windows |
| `scoop`, `choco` | Scoop apps and Chocolatey packages | Windows |

Collectors read metadata files wherever they can. bomwatch never runs a Python
found under the roots, and never runs a program it finds; the version of a
`.exe` is read from its version resource.

A missing tool (no npm, no docker) is skipped, not an error. A tool that is
there but fails (docker without its daemon) marks the collector `failed`, so
its packages are not reported as removed.

**Roots.** The `pip` and `npm-project` collectors search the roots. The
default root is the home directory of the user who runs bomwatch. `--root`
replaces that default; it does not add to it. Give `--root` more than once to
search several places. A cron job that runs as root scans `/root` only, unless
you pass `--root`.

**Snapshots** go to `--state-dir`, else `$BOMWATCH_STATE_DIR`, else
`~/.local/state/bomwatch/snapshots/` (`%LOCALAPPDATA%\bomwatch\snapshots` on
Windows), one `scan-YYYYMMDDTHHMMSSZ.json` per scan. A scan is written to a
temporary file and moved into place, so a crash never leaves half a file; two
scans at once never overwrite each other. A file that still cannot be read is
skipped with a warning.

## Windows

`bomwatch scan` on Windows reads the same "Installed apps" list as Settings,
plus Store apps, Scoop, Chocolatey, Steam and loose programs. Say Godot
appeared on your machine. Depending on how it got there, it shows up as:

```text
+ windows Godot Engine 4.3 (user)                          # winget or an installer
+ portable Godot_v4.3-stable_win64.exe 4.3.0.0 (C:\Users\me\Downloads\Godot_v4.3-stable_win64)
+ steam Godot Engine 15432100 (C:\Program Files (x86)\Steam\steamapps)
+ scoop godot 4.3 (C:\Users\me\scoop)
+ choco godot 4.3.0 (C:\ProgramData\chocolatey\lib)
```

To check every 15 minutes, register a scheduled task with
`contrib/windows/install-task.ps1`. It appends changes to
`%LOCALAPPDATA%\bomwatch\changes.log`.

## Reading a diff

Diff lines: `+` added, `-` removed, `^` upgraded, `v` downgraded, `~` changed
(no order, such as a new image id), `!` known vulnerability (with `--vulns`).

Versions are compared the way each ecosystem does: Debian rules for dpkg
(`1.0~rc1` < `1.0`), rpmvercmp for rpm, PEP 440 for pip (`1.0rc1` < `1.0` <
`1.0.post1`) and semver for npm, cargo, go and editor extensions. Going from a
pre-release to the release is an upgrade.

bomwatch does not report false removals:

- An ecosystem is compared only when both scans collected it without error.
  A collector left out with `--only`, or one whose tool failed, gives a note
  (`note: npm not compared (skipped in NEW)`) instead of removals. So does a
  collector that did not exist yet when an old scan was made
  (`not run in OLD`).
- `bomwatch diff` with no files compares each ecosystem with the newest older
  scan where that ecosystem was ok. A package installed while npm was failing
  is still reported on the next full scan. `bomwatch diff OLD NEW` compares
  only those two files.
- Each snapshot records its roots. `pip` and `npm-project` are compared only
  with a scan of the same roots (`note: pip not compared (other roots in OLD)`).

With only one scan, `bomwatch diff` prints `first scan, nothing to compare`
and `bomwatch diff --json` prints `{"first_scan": true, ...}` with empty lists.

## Vulnerabilities

`bomwatch vulns` and `bomwatch diff --vulns` send the name, ecosystem and
version of packages to the [OSV API](https://google.github.io/osv.dev/api/);
nothing else leaves the machine, and nothing is sent without one of these
flags. Covered: pip, npm, npm-project, cargo, go, and dpkg on Debian and
Ubuntu (looked up by source package, so `libssl3` is checked as `openssl`).
Other collectors are not sent.

## SBOM export

`bomwatch export` writes CycloneDX 1.5 (default) or SPDX 2.3 JSON. Each
component has a [package URL](https://github.com/package-url/purl-spec)
(`pkg:pypi/jinja2@3.1.4`, `pkg:deb/ubuntu/libc6@2.39-0ubuntu8?arch=amd64`,
`pkg:npm/%40scope/tool@1.0.0`), so the file can go into Dependency-Track,
Grype or any other SBOM tool. Ecosystems without a purl type use
`pkg:generic/<collector>/<name>`.

## Watching

`bomwatch watch` scans every `--interval` seconds (default 300) and prints a
line for every change, prefixed with the time; `--json` prints one JSON object
per change set. A snapshot is saved only when something changed, so the
history stays small. `bomwatch log NAME` then shows the story of one package:

```text
2026-09-27T20:37:24Z  + pip jinja2 2.10 (/home/me/proj/.venv)
2026-09-27T20:37:25Z  ^ pip jinja2 2.10 -> 3.1.4 (/home/me/proj/.venv)
```

For a systemd user service (`watch`) or timer (`scan` + `diff`), see
`contrib/systemd/`.

## Exit codes

| code | meaning |
|---|---|
| 0 | success, no changes |
| 1 | error |
| 2 | usage error (also `bomwatch` with no command) |
| 3 | success, changes found |
| 4 | success, known vulnerabilities found (`vulns`, `diff --vulns`) |

## Development

```sh
make check        # mypy, black --check, ruff, pylint (>= 9.5), pytest with branch coverage (>= 85 %)
make format       # black and ruff --fix
make integration  # real scan/install/diff run; needs dpkg, npm and network
pre-commit install
```

CI (`.github/workflows/ci.yml`) runs lint, the tests on Python 3.10 to 3.14 and
macOS, the Windows collectors against a real Windows registry, and the
integration script in a Debian container. CodeQL and Dependabot are set up too.

The site in `docs/` is published by `.github/workflows/pages.yml`. Turn it on
once under Settings > Pages > Source: GitHub Actions.

## Licence

MIT
