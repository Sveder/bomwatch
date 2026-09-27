"""System package managers besides dpkg: rpm, snap and flatpak."""

from bomwatch.model import Package
from bomwatch.runner import has, run

RPM_FORMAT = r"%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\n"
FLATPAK_COLUMNS = "application,version,branch,installation"


def parse_rpm(output):
    """Turn ``rpm -qa`` output into packages; the version is ``[epoch:]ver-rel``."""
    packages = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0]:
            name, version, arch = parts
            packages.append(Package("rpm", name, version, arch, "rpm"))
    return packages


def collect_rpm(_roots):
    """Return installed RPM packages; [] without rpm, None if it fails."""
    if not has("rpm"):
        return []
    output = run(["rpm", "-qa", "--queryformat", RPM_FORMAT])
    return None if output is None else parse_rpm(output)


def parse_snap(output):
    """Turn ``snap list`` output (a table with a header) into packages."""
    packages = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3:
            packages.append(Package("snap", parts[0], parts[1], "", "snap"))
    return packages


def collect_snap(_roots):
    """Return installed snaps; [] without snap, None if it fails."""
    if not has("snap"):
        return []
    output = run(["snap", "list"])
    return None if output is None else parse_snap(output)


def parse_flatpak(output):
    """Turn ``flatpak list --columns=...`` output into packages.

    Runtimes are installed once per branch, so the location is
    ``installation/branch``. An app with no version uses its branch.
    """
    packages = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or not parts[0] or parts[0] == "Application ID":
            continue
        app, version, branch, installation = (p.strip() for p in parts)
        packages.append(
            Package(
                "flatpak", app, version or branch, f"{installation}/{branch}", "flatpak"
            )
        )
    return packages


def collect_flatpak(_roots):
    """Return installed flatpak apps and runtimes; [] without flatpak."""
    if not has("flatpak"):
        return []
    output = run(["flatpak", "list", f"--columns={FLATPAK_COLUMNS}"])
    return None if output is None else parse_flatpak(output)
