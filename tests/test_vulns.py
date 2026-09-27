import io
import json

import pytest

from bomwatch import vulns
from bomwatch.model import Package


@pytest.mark.parametrize(
    "pkg,system,expected",
    [
        (Package("pip", "jinja2", "2.10"), {}, ("PyPI", "jinja2")),
        (Package("npm", "lodash", "4.0.0"), {}, ("npm", "lodash")),
        (Package("npm-project", "lodash", "4.0.0"), {}, ("npm", "lodash")),
        (Package("cargo", "time", "0.1.0"), {}, ("crates.io", "time")),
        (
            Package(
                "go",
                "golang.org/x/tools/gopls",
                "v0.1.0",
                "",
                "golang.org/x/tools/gopls",
            ),
            {},
            ("Go", "golang.org/x/tools/gopls"),
        ),
        (Package("go", "cmd/x", "go1.20", "", "go"), {}, ("Go", "cmd/x")),
        (
            Package("dpkg", "libssl3", "3.0.2", "amd64", "openssl"),
            {"id": "ubuntu", "version_id": "22.04", "version": "22.04.4 LTS (Jammy)"},
            ("Ubuntu:22.04:LTS", "openssl"),
        ),
        (
            Package("dpkg", "bash", "5.2", "amd64", "dpkg"),
            {"id": "ubuntu", "version_id": "24.10", "version": "24.10"},
            ("Ubuntu:24.10", "bash"),
        ),
        (
            Package("dpkg", "bash", "5.2", "amd64", "bash"),
            {"id": "debian", "version_id": "12"},
            ("Debian:12", "bash"),
        ),
    ],
)
def test_query(pkg, system, expected):
    query = vulns.query(pkg, system)
    assert (query["package"]["ecosystem"], query["package"]["name"]) == expected
    assert query["version"] == pkg.version


@pytest.mark.parametrize(
    "pkg,system",
    [
        (Package("dpkg", "bash", "5.2"), {"id": "debian"}),
        (Package("dpkg", "bash", "5.2"), {"id": "arch", "version_id": "1"}),
        (Package("docker", "nginx", "sha256:aa"), {}),
        (Package("pip", "x", ""), {}),
    ],
)
def test_query_not_covered(pkg, system):
    assert vulns.query(pkg, system) is None


class Answer(io.BytesIO):
    """A urlopen answer."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_lookup_and_summaries(monkeypatch):
    sent = []

    def urlopen(request, timeout):  # pylint: disable=unused-argument
        sent.append(request)
        if request.full_url.endswith("querybatch"):
            body = json.loads(request.data)
            assert len(body["queries"]) == 2
            results = [{"vulns": [{"id": "B"}, {"id": "A"}]}, {}]
            return Answer(json.dumps({"results": results}).encode())
        if request.full_url.endswith("/A"):
            return Answer(json.dumps({"summary": "bad thing"}).encode())
        if request.full_url.endswith("/B"):
            return Answer(json.dumps({"details": "long details"}).encode())
        raise OSError("down")

    monkeypatch.setattr(vulns.urllib.request, "urlopen", urlopen)
    old = Package("pip", "jinja2", "2.10", "/env")
    packages = [old, Package("npm", "ok", "1.0.0"), Package("docker", "x", "y")]
    found = vulns.lookup(packages)
    assert found == {old: ["A", "B"]}
    details = vulns.summaries(["A", "B", "C"])
    assert details == {"A": "bad thing", "B": "long details"}
    lines = vulns.report(found, details)
    assert lines[0] == "! pip jinja2 2.10 (/env)"
    assert "A  bad thing  https://osv.dev/vulnerability/A" in lines[1]
    assert vulns.to_dict(found)[0]["vulns"] == [
        {"id": "A", "summary": ""},
        {"id": "B", "summary": ""},
    ]
    assert sent[0].get_header("User-agent").startswith("bomwatch/")
