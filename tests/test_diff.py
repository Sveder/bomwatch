import pytest

from bomwatch import diff
from bomwatch.model import Package


def pkg(name, version, eco="pip"):
    return Package(eco, name, version, "/env")


@pytest.mark.parametrize(
    "low,high",
    [
        ("1.9", "1.10"),
        ("2.0", "1:0.1"),
        ("1.0", "1.0.1"),
        ("1.0a", "1.0b"),
        ("9", "10"),
    ],
)
def test_version_key(low, high):
    assert diff.version_key(low) < diff.version_key(high)


def test_compare_all_kinds():
    old = [pkg("gone", "1"), pkg("up", "1.9"), pkg("down", "2"), pkg("same", "1")]
    new = [pkg("new", "1"), pkg("up", "1.10"), pkg("down", "1"), pkg("same", "1")]
    changes = diff.compare(old, new)
    assert changes["added"] == [pkg("new", "1")]
    assert changes["removed"] == [pkg("gone", "1")]
    assert changes["upgraded"] == [{"old": pkg("up", "1.9"), "new": pkg("up", "1.10")}]
    assert changes["downgraded"] == [{"old": pkg("down", "2"), "new": pkg("down", "1")}]
    assert not diff.is_empty(changes)


def test_same_order_different_string_is_upgrade():
    changes = diff.compare([pkg("a", "1.0")], [pkg("a", "1.00")])
    assert len(changes["upgraded"]) == 1


def test_no_changes():
    assert diff.is_empty(diff.compare([pkg("a", "1")], [pkg("a", "1")]))


def test_to_dict_and_lines():
    changes = diff.compare(
        [pkg("a", "1"), pkg("b", "2")], [pkg("a", "2"), pkg("c", "1")]
    )
    data = diff.to_dict(changes)
    assert data["added"][0]["name"] == "c"
    assert data["upgraded"][0]["new"]["version"] == "2"
    assert diff.to_lines(changes) == [
        "+ pip c 1 (/env)",
        "- pip b 2 (/env)",
        "^ pip a 1 -> 2 (/env)",
    ]
    down = diff.compare([pkg("a", "2")], [pkg("a", "1")])
    assert diff.to_lines(down) == ["v pip a 2 -> 1 (/env)"]


def test_not_compared_reasons():
    old = {"dpkg": "ok", "npm": "ok", "pip": "skipped"}
    new = {"dpkg": "ok", "npm": "failed", "pip": "failed"}
    assert diff.not_compared(old, new) == {
        "npm": "failed in NEW",
        "pip": "skipped in OLD, failed in NEW",
    }


def test_not_compared_missing_status_is_ok():
    assert not diff.not_compared({}, {"dpkg": "ok"})


def test_compare_skips_ecosystems():
    old = [pkg("a", "1"), pkg("b", "1", eco="npm")]
    assert diff.is_empty(diff.compare(old, [pkg("a", "1")], skip={"npm"}))


def test_roots_differ():
    assert diff.roots_differ(["/a"], ["/b"], ("pip", "npm")) == {
        "npm": "roots differ",
        "pip": "roots differ",
    }
    assert not diff.roots_differ(["/a"], ["/a"], ("pip",))
    assert not diff.roots_differ(None, ["/a"], ("pip",))
