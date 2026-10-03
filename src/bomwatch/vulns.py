"""Look up known vulnerabilities in the OSV database (https://osv.dev).

Only the package name, ecosystem and version are sent. Ecosystems OSV does
not cover (docker images, apps, editor extensions ...) are not sent at all.
"""

from __future__ import annotations

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bomwatch import __version__
from bomwatch.model import Package

API = "https://api.osv.dev/v1"
BATCH = 1000
TIMEOUT = 30
DETAIL_LIMIT = 100
APT_LISTS = Path("/var/lib/apt/lists")
DISTRO_ORIGINS = {"Ubuntu", "Debian"}


def debian_ecosystem(system: dict) -> str | None:
    """Return the OSV ecosystem of a Debian or Ubuntu release, or None."""
    distro, release = system.get("id"), system.get("version_id")
    if not release:
        return None
    if distro == "debian":
        return f"Debian:{release}"
    if distro == "ubuntu":
        lts = ":LTS" if "LTS" in system.get("version", "") else ""
        return f"Ubuntu:{release}{lts}"
    return None


def release_origin(path: Path) -> str:
    """Return the ``Origin:`` field of an apt Release or InRelease file."""
    try:
        for line in path.read_text(errors="replace").splitlines():
            if line.startswith("Origin:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return ""


def third_party_debs(lists_dir: Path = APT_LISTS) -> set[tuple[str, str]]:
    """Return ``{(name, version)}`` of the debs that other apt repos ship.

    A repo whose Release file names an origin other than Ubuntu or Debian
    (Netdata, Docker, Tailscale ...) is third party. Its packages share names
    with the distro packages, but not the version scheme. The distro records
    in OSV often list a CVE as unfixed for every version, so a query with a
    third-party version always matches and gives a false alarm.
    """
    if not lists_dir.is_dir():
        return set()
    prefixes = []
    for release in lists_dir.iterdir():
        name = release.name
        for suffix in ("_InRelease", "_Release"):
            if name.endswith(suffix):
                if release_origin(release) not in DISTRO_ORIGINS:
                    prefixes.append(name[: -len(suffix) + 1])
    found: set[tuple[str, str]] = set()
    for index in lists_dir.iterdir():
        if not index.name.endswith("_Packages"):
            continue
        if not any(index.name.startswith(p) for p in prefixes):
            continue
        package = ""
        try:
            for line in index.read_text(errors="replace").splitlines():
                if line.startswith("Package:"):
                    package = line.split(":", 1)[1].strip()
                elif line.startswith("Version:") and package:
                    found.add((package, line.split(":", 1)[1].strip()))
        except OSError:
            continue
    return found


def query(pkg: Package, system: dict | None = None) -> dict | None:
    """Return the OSV query for ``pkg``, or None when OSV does not cover it."""
    system = system or {}
    name = pkg.name
    ecosystem: str | None
    if pkg.ecosystem == "pip":
        ecosystem = "PyPI"
    elif pkg.ecosystem in ("npm", "npm-project"):
        ecosystem = "npm"
    elif pkg.ecosystem == "cargo":
        ecosystem = "crates.io"
    elif pkg.ecosystem == "go":
        ecosystem = "Go"
        name = pkg.source if pkg.source not in ("", "go") else pkg.name
    elif pkg.ecosystem == "dpkg":
        ecosystem = debian_ecosystem(system)
        # Debian advisories name the source package (openssl, not libssl3).
        name = pkg.source if pkg.source not in ("", "dpkg") else pkg.name
    else:
        ecosystem = None
    if not ecosystem or not pkg.version:
        return None
    return {"package": {"ecosystem": ecosystem, "name": name}, "version": pkg.version}


def post(url: str, body: dict) -> dict:
    """POST ``body`` as JSON and return the JSON answer."""
    request = urllib.request.Request(  # noqa: S310
        url,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"bomwatch/{__version__}",
        },
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:  # noqa: S310
        return json.load(answer)


def get(url: str) -> dict:
    """GET ``url`` and return the JSON answer."""
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": f"bomwatch/{__version__}"}
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:  # noqa: S310
        return json.load(answer)


def lookup(packages, system=None, lists_dir=APT_LISTS) -> dict[Package, list[str]]:
    """Return ``{package: [vulnerability ids]}`` for the packages with known vulns.

    Debs from third-party apt repos are not sent: OSV holds no records for
    those repos, only distro records that do not match their versions.

    Raises OSError when OSV cannot be reached.
    """
    foreign = third_party_debs(lists_dir) if lists_dir else set()
    wanted = [
        (p, q)
        for p in packages
        if not (p.ecosystem == "dpkg" and (p.name, p.version) in foreign)
        and (q := query(p, system))
    ]
    found: dict[Package, list[str]] = {}
    for start in range(0, len(wanted), BATCH):
        chunk = wanted[start : start + BATCH]
        answer = post(f"{API}/querybatch", {"queries": [q for _, q in chunk]})
        for (pkg, _), result in zip(chunk, answer.get("results", []), strict=False):
            ids = sorted({v["id"] for v in (result or {}).get("vulns", []) or []})
            if ids:
                found[pkg] = ids
    return found


def summaries(ids, limit=DETAIL_LIMIT) -> dict[str, str]:
    """Return ``{id: summary}`` for up to ``limit`` ids; failures are left out."""

    def one(vuln_id):
        try:
            data = get(f"{API}/vulns/{vuln_id}")
        except (OSError, ValueError):
            return vuln_id, ""
        return vuln_id, data.get("summary") or data.get("details", "")[:120]

    ids = sorted(set(ids))[:limit]
    with ThreadPoolExecutor(max_workers=8) as pool:
        return {k: v for k, v in pool.map(one, ids) if v}


def report(found, details=None) -> list[str]:
    """Return text lines for ``lookup`` results."""
    details = details or {}
    lines = []
    for pkg in sorted(found):
        lines.append(f"! {pkg.ecosystem} {pkg.name} {pkg.version} ({pkg.location})")
        for vuln_id in found[pkg]:
            summary = f"  {details[vuln_id]}" if details.get(vuln_id) else ""
            lines.append(
                f"    {vuln_id}{summary}  https://osv.dev/vulnerability/{vuln_id}"
            )
    return lines


def to_dict(found, details=None) -> list[dict]:
    """Return ``lookup`` results as plain dicts."""
    details = details or {}
    return [
        {
            "package": pkg.to_dict(),
            "vulns": [{"id": i, "summary": details.get(i, "")} for i in found[pkg]],
        }
        for pkg in sorted(found)
    ]
