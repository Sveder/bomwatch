import re

import pytest

from bomwatch import export
from bomwatch.model import Package

UBUNTU = {"id": "ubuntu", "version_id": "24.04"}


@pytest.mark.parametrize(
    "pkg,system,expected",
    [
        (
            Package("dpkg", "libc6", "2.39-0ubuntu8", "amd64"),
            UBUNTU,
            "pkg:deb/ubuntu/libc6@2.39-0ubuntu8?arch=amd64",
        ),
        (
            Package("dpkg", "bash", "1:5.2", "amd64"),
            {},
            "pkg:deb/debian/bash@1%3A5.2?arch=amd64",
        ),
        (
            Package("rpm", "openssl", "1:3.0.7-24.el9", "x86_64"),
            {"id": "rocky"},
            "pkg:rpm/rocky/openssl@3.0.7-24.el9?arch=x86_64&epoch=1",
        ),
        (
            Package("rpm", "bash", "5.2-3", "x86_64"),
            {"id": "arch"},
            "pkg:rpm/rpm/bash@5.2-3?arch=x86_64",
        ),
        (Package("pip", "requests", "2.32.0"), {}, "pkg:pypi/requests@2.32.0"),
        (Package("npm", "@scope/tool", "1.0.0"), {}, "pkg:npm/%40scope/tool@1.0.0"),
        (Package("npm-project", "left-pad", "1.3.0"), {}, "pkg:npm/left-pad@1.3.0"),
        (Package("cargo", "ripgrep", "14.1.0"), {}, "pkg:cargo/ripgrep@14.1.0"),
        (
            Package("go", "golang.org/x/tools/gopls", "v0.15.2"),
            {},
            "pkg:golang/golang.org/x/tools/gopls@v0.15.2",
        ),
        (
            Package("docker", "library/nginx", "sha256:aa", "latest"),
            {},
            "pkg:docker/library/nginx@sha256%3Aaa?tag=latest",
        ),
        (
            Package("podman", "alpine", "sha256:bb", ""),
            {},
            "pkg:docker/alpine@sha256%3Abb",
        ),
        (Package("brew", "jq", "1.7"), {}, "pkg:generic/homebrew/jq@1.7"),
        (
            Package("windows", "Godot Engine", "4.3"),
            {},
            "pkg:generic/windows/Godot%20Engine@4.3",
        ),
        (Package("portable", "tool.exe", ""), {}, "pkg:generic/portable/tool.exe"),
    ],
)
def test_purl(pkg, system, expected):
    assert export.purl(pkg, system) == expected


SNAP = {
    "created": "2026-09-27T01:02:03Z",
    "host": "box",
    "os": UBUNTU,
    "packages": [
        Package("pip", "requests", "2.32.0", "/env", "venv"),
        Package("docker", "nginx", "sha256:aa", "latest", "docker"),
        Package("portable", "tool.exe", "", "/dl", "file"),
    ],
}


def test_cyclonedx():
    doc = export.export(SNAP, "cyclonedx")
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert re.match(r"urn:uuid:[0-9a-f-]{36}$", doc["serialNumber"])
    assert doc["metadata"]["component"]["name"] == "box"
    types = [c["type"] for c in doc["components"]]
    assert types == ["library", "container", "application"]
    assert "version" not in doc["components"][2]
    refs = {c["bom-ref"] for c in doc["components"]}
    assert len(refs) == 3


def test_spdx():
    doc = export.export({**SNAP, "os": None}, "spdx")
    assert doc["spdxVersion"] == "SPDX-2.3"
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert ids[0] == "SPDXRef-host" and len(set(ids)) == 4
    assert all(re.match(r"SPDXRef-[A-Za-z0-9.-]+$", i) for i in ids)
    assert len(doc["relationships"]) == 4
    assert doc["packages"][1]["externalRefs"][0]["referenceLocator"] == (
        "pkg:pypi/requests@2.32.0"
    )
    assert "versionInfo" not in doc["packages"][3]
