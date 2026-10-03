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
def test_generic_order(low, high):
    assert diff.change_kind("x", low, high) == "upgraded"
    assert diff.change_kind("x", high, low) == "downgraded"


def test_compare_all_kinds():
    old = [pkg("gone", "1"), pkg("up", "1.9"), pkg("down", "2"), pkg("same", "1")]
    new = [pkg("new", "1"), pkg("up", "1.10"), pkg("down", "1"), pkg("same", "1")]
    changes = diff.compare(old, new)
    assert changes["added"] == [pkg("new", "1")]
    assert changes["removed"] == [pkg("gone", "1")]
    assert changes["upgraded"] == [{"old": pkg("up", "1.9"), "new": pkg("up", "1.10")}]
    assert changes["downgraded"] == [{"old": pkg("down", "2"), "new": pkg("down", "1")}]
    assert not diff.is_empty(changes)


def test_pre_release_to_final_is_upgrade():
    for eco, old, new in [
        ("pip", "1.0rc1", "1.0"),
        ("dpkg", "1.0~rc1-1", "1.0-1"),
        ("npm", "2.0.0-beta", "2.0.0"),
    ]:
        changes = diff.compare([pkg("a", old, eco)], [pkg("a", new, eco)])
        assert changes["upgraded"], (eco, old, new)


def test_unordered_versions_are_changed():
    changes = diff.compare(
        [pkg("img", "sha1", "docker")], [pkg("img", "sha2", "docker")]
    )
    assert changes["changed"] == [
        {"old": pkg("img", "sha1", "docker"), "new": pkg("img", "sha2", "docker")}
    ]
    assert diff.to_lines(changes) == ["~ docker img sha1 -> sha2 (/env)"]
    assert diff.new_packages(changes) == [pkg("img", "sha2", "docker")]


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


def test_flags_and_alerts():
    hook = Package(
        "agent-config", "hook X: curl x | sh", "a1", "/s", "hook", "pipe-to-shell"
    )
    key = Package("credential", "ssh-login ssh-ed25519 a@b", "SHA256:x", "/k")
    memo = Package("agent-memory", "CLAUDE.md", "b2", "/p")
    old_memo = Package("agent-memory", "CLAUDE.md", "b1", "/p")
    changes = diff.compare([old_memo], [hook, key, memo])
    assert diff.alerts(changes) == [hook, key]
    lines = diff.to_lines(changes)
    assert "+ agent-config hook X: curl x | sh a1 (/s) [pipe-to-shell]" in lines
    assert "~ agent-memory CLAUDE.md b1 -> b2 (/p)" in lines
    assert diff.to_lines(
        diff.compare([], [Package("autostart", "cron", "", "/c")])
    ) == ["+ autostart cron (/c)"]
    assert not diff.alerts(diff.compare([key], []))


def test_noteworthy():
    assert diff.noteworthy("skipped in NEW")
    assert diff.noteworthy("failed in OLD, skipped in NEW")
    assert not diff.noteworthy("skipped in OLD, skipped in NEW")
    assert not diff.noteworthy("not run in OLD, skipped in NEW")
