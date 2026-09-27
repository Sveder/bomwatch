"""Debian packages from dpkg."""

from bomwatch.model import Package
from bomwatch.runner import has, run

FORMAT = (
    r"${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}"
    r"\t${source:Package}\n"
)
NOT_INSTALLED = "nc"


def parse(output):
    """Turn ``dpkg-query -W`` output into packages on disk.

    The second status letter is the package state; ``n`` (not installed) and
    ``c`` (config files only) are left out, held and half-installed are kept.
    ``source`` is the Debian source package (``openssl`` for ``libssl3``), which
    is the name security advisories use. Output without that column (older
    snapshots, tests) gets ``dpkg``.
    """
    packages = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) not in (4, 5) or len(parts[0]) < 2:
            continue
        if parts[0][1] in NOT_INSTALLED:
            continue
        _, name, version, arch = parts[:4]
        source = parts[4] if len(parts) == 5 and parts[4] else "dpkg"
        packages.append(Package("dpkg", name, version, arch, source))
    return packages


def collect(_roots):
    """Return installed dpkg packages; [] without dpkg, None if dpkg-query fails."""
    if not has("dpkg-query"):
        return []
    output = run(["dpkg-query", "-W", "-f", FORMAT])
    return None if output is None else parse(output)
