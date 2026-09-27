# bomwatch

A software bill of materials (SBOM) for the machine it runs on, and an alert
when new software appears. Built for machines where AI agents install packages
on their own.

Status: early work. Not released yet.

## Install

```sh
git clone https://github.com/Sveder/bomwatch.git
cd bomwatch
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'     # or: make install
bomwatch --version
```

Python 3.10 or newer. No other dependencies at run time.

## Quick start

```sh
bomwatch scan     # list installed software, save a snapshot
# ... install something ...
bomwatch scan
bomwatch diff     # what changed since the scan before
```

A full scan of a server with 2437 packages takes about 0.9 s.

## Commands

```sh
bomwatch scan                          # all collectors, save a snapshot
bomwatch scan --only dpkg,pip          # some collectors only
bomwatch scan --root /srv --root ~     # where to look for envs
bomwatch scan --json --no-save         # counts as JSON, nothing written
bomwatch diff                          # last scan against the ones before
bomwatch diff OLD.json NEW.json --json # two named snapshots
```

Collectors:

- `dpkg`: Debian and Ubuntu packages.
- `pip`: the system Python, user-site, and every venv or conda env under the
  roots. Envs are read from their metadata files; bomwatch never runs a Python
  found under the roots. Names are PEP 503 normalized. User-site packages,
  and envs with more than one `lib/python3.N`, get a `/python3.N` suffix on
  their location.
- `npm`: global packages of every nvm node version.

A missing tool (no npm, no docker) is skipped, not an error.

**Roots.** The default root is the home directory of the user who runs
bomwatch. `--root` replaces that default; it does not add to it. Give
`--root` more than once to search several places. A cron job that runs as
root scans `/root` only, unless you pass `--root`.

**Snapshots** go to `--state-dir`, else `$BOMWATCH_STATE_DIR`, else
`~/.local/state/bomwatch/snapshots/`, one `scan-YYYYMMDDTHHMMSSZ.json` per scan.

## Reading a diff

Diff lines: `+` added, `-` removed, `^` upgraded, `v` downgraded.

bomwatch does not report false removals:

- An ecosystem is compared only when both scans collected it without error.
  A collector left out with `--only`, or one whose tool failed, gives a note
  (`note: npm not compared (skipped in NEW)`) instead of removals.
- `bomwatch diff` with no files compares each ecosystem with the newest older
  scan where that ecosystem was ok. A package installed while npm was failing
  is still reported on the next full scan. `bomwatch diff OLD NEW` compares
  only those two files.
- Each snapshot records its roots. `pip` is compared only with a scan of the
  same roots (`note: pip not compared (other roots in OLD)`).

With only one scan, `bomwatch diff` prints `first scan, nothing to compare`
and `bomwatch diff --json` prints `{"first_scan": true, ...}` with empty lists.

## Exit codes

| code | meaning |
|---|---|
| 0 | success, no changes |
| 1 | error |
| 2 | usage error (also `bomwatch` with no command) |
| 3 | success, changes found |

## Development

```sh
make check   # black --check, pylint on src and tests (>= 9.5), pytest with branch coverage (>= 85 %)
make format  # black
```

## Licence

MIT

## CI

A GitHub Actions workflow is in `ci/github-actions.yml`. Copy it to `.github/workflows/ci.yml` to turn it on.
