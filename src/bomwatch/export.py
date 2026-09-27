"""Export a snapshot as a CycloneDX 1.5 or SPDX 2.3 JSON document."""

from __future__ import annotations

import hashlib
import uuid
from urllib.parse import quote

from bomwatch import __version__
from bomwatch.model import Package

FORMATS = ("cyclonedx", "spdx")
TOOL_URL = "https://github.com/Sveder/bomwatch"
RPM_DISTROS = {"rhel", "centos", "fedora", "almalinux", "rocky", "opensuse", "amzn"}


def _q(text: str) -> str:
    """Percent-encode one purl segment."""
    return quote(text, safe="")


def _deb_namespace(system: dict) -> str:
    """Return the purl namespace for Debian-like systems: ``debian``, ``ubuntu``..."""
    return system.get("id") or "debian"


def purl(pkg: Package, system: dict | None = None) -> str:
    """Return the package URL (purl) of ``pkg``.

    ``system`` is the snapshot's ``os`` record, used for the distro of dpkg and
    rpm packages. Ecosystems with no purl type use ``pkg:generic``.
    """
    system = system or {}
    name, version = _q(pkg.name), _q(pkg.version)
    at = f"@{version}" if pkg.version else ""
    eco = pkg.ecosystem
    if eco == "dpkg":
        return f"pkg:deb/{_deb_namespace(system)}/{name}{at}?arch={_q(pkg.location)}"
    if eco == "rpm":
        distro = system.get("id") if system.get("id") in RPM_DISTROS else "rpm"
        epoch, sep, rest = pkg.version.partition(":")
        if sep and epoch.isdigit():
            return (
                f"pkg:rpm/{distro}/{name}@{_q(rest)}"
                f"?arch={_q(pkg.location)}&epoch={epoch}"
            )
        return f"pkg:rpm/{distro}/{name}{at}?arch={_q(pkg.location)}"
    if eco == "pip":
        return f"pkg:pypi/{name}{at}"
    if eco in ("npm", "npm-project"):
        scope, _, bare = pkg.name.rpartition("/")
        prefix = f"{_q(scope)}/" if scope else ""
        return f"pkg:npm/{prefix}{_q(bare)}{at}"
    if eco == "cargo":
        return f"pkg:cargo/{name}{at}"
    if eco == "go":
        path = "/".join(_q(part) for part in pkg.name.split("/"))
        return f"pkg:golang/{path}{at}"
    if eco in ("docker", "podman"):
        path = "/".join(_q(part) for part in pkg.name.split("/"))
        tag = f"?tag={_q(pkg.location)}" if pkg.location else ""
        return f"pkg:docker/{path}@{version}{tag}"
    if eco == "brew":
        return f"pkg:generic/homebrew/{name}{at}"
    return f"pkg:generic/{_q(eco)}/{name}{at}"


def component_type(pkg: Package) -> str:
    """Return the CycloneDX component type of ``pkg``."""
    if pkg.ecosystem in ("docker", "podman"):
        return "container"
    if pkg.ecosystem in ("pip", "npm", "npm-project", "cargo", "vscode"):
        return "library"
    return "application"


def ref(pkg: Package) -> str:
    """Return a reference that is unique for each package of a snapshot."""
    raw = "\0".join((pkg.ecosystem, pkg.name, pkg.location, pkg.version))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def cyclonedx(snap: dict) -> dict:
    """Return ``snap`` as a CycloneDX 1.5 JSON document."""
    system = snap.get("os") or {}
    components = []
    for pkg in snap["packages"]:
        component = {
            "type": component_type(pkg),
            "bom-ref": f"{pkg.ecosystem}-{ref(pkg)}",
            "name": pkg.name,
            "purl": purl(pkg, system),
            "properties": [
                {"name": "bomwatch:ecosystem", "value": pkg.ecosystem},
                {"name": "bomwatch:location", "value": pkg.location},
                {"name": "bomwatch:source", "value": pkg.source},
            ],
        }
        if pkg.version:
            component["version"] = pkg.version
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": snap["created"],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "bomwatch",
                        "version": __version__,
                        "externalReferences": [{"type": "website", "url": TOOL_URL}],
                    }
                ]
            },
            "component": {
                "type": "device",
                "bom-ref": "host",
                "name": snap.get("host", "unknown"),
                "properties": [
                    {"name": f"bomwatch:os:{k}", "value": str(v)}
                    for k, v in sorted(system.items())
                ],
            },
        },
        "components": components,
    }


def spdx(snap: dict) -> dict:
    """Return ``snap`` as an SPDX 2.3 JSON document."""
    system = snap.get("os") or {}
    host = snap.get("host", "unknown")
    packages = [
        {
            "SPDXID": "SPDXRef-host",
            "name": host,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": "DEVICE",
        }
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-host",
        }
    ]
    for pkg in snap["packages"]:
        spdx_id = f"SPDXRef-{pkg.ecosystem}-{ref(pkg)}"
        entry = {
            "SPDXID": spdx_id,
            "name": pkg.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "comment": f"{pkg.ecosystem} at {pkg.location or '-'} ({pkg.source})",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl(pkg, system),
                }
            ],
        }
        if pkg.version:
            entry["versionInfo"] = pkg.version
        packages.append(entry)
        relationships.append(
            {
                "spdxElementId": "SPDXRef-host",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id,
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"bomwatch-{host}-{snap['created']}",
        "documentNamespace": f"{TOOL_URL}/spdx/{_q(host)}/{uuid.uuid4()}",
        "creationInfo": {
            "created": snap["created"],
            "creators": [f"Tool: bomwatch-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def export(snap: dict, fmt: str) -> dict:
    """Return ``snap`` in format ``fmt`` (one of ``FORMATS``)."""
    return cyclonedx(snap) if fmt == "cyclonedx" else spdx(snap)
