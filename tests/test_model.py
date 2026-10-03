from bomwatch.model import Package


def test_to_dict_and_key():
    pkg = Package("pip", "rich", "13.0", "/env", "venv")
    assert pkg.to_dict() == {
        "ecosystem": "pip",
        "name": "rich",
        "version": "13.0",
        "location": "/env",
        "source": "venv",
    }
    assert pkg.key == ("pip", "rich", "/env")


def test_sorting_is_stable():
    first = Package("dpkg", "a", "1")
    second = Package("dpkg", "b", "1")
    assert sorted([second, first]) == [first, second]


def test_flags_only_in_dict_when_set():
    assert "flags" not in Package("pip", "a", "1").to_dict()
    assert (
        Package("mcp", "a", "1", flags="remote-http").to_dict()["flags"]
        == "remote-http"
    )
