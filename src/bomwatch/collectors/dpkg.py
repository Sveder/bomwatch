"""Debian packages from dpkg."""

from bomwatch.model import Package
from bomwatch.runner import has, run

FORMAT = r"${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n"
NOT_INSTALLED = "nc"


def parse(output):
    """Turn ``dpkg-query -W`` output into packages on disk.

    The second status letter is the package state; ``n`` (not installed) and
    ``c`` (config files only) are left out, held and half-installed are kept.
    """
    packages = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or len(parts[0]) < 2:
            continue
        if parts[0][1] in NOT_INSTALLED:
            continue
        _, name, version, arch = parts
        packages.append(Package("dpkg", name, version, arch, "dpkg"))
    return packages


def collect(_roots):
    """Return installed dpkg packages; [] without dpkg, None if dpkg-query fails."""
    if not has("dpkg-query"):
        return []
    output = run(["dpkg-query", "-W", "-f", FORMAT])
    return None if output is None else parse(output)
