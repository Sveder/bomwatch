from pathlib import Path

from bomwatch import collectors
from bomwatch.model import Package


def fake(name):
    return lambda roots: [Package(name, "x", "1", str(roots[0]))]


def test_collect_all_sorts_and_dedupes(monkeypatch):
    monkeypatch.setattr(
        collectors,
        "COLLECTORS",
        {"b": fake("b"), "a": fake("a"), "a2": fake("a")},
    )
    packages, status = collectors.collect_all(roots=["/r"])
    assert packages == [Package("a", "x", "1", "/r"), Package("b", "x", "1", "/r")]
    assert status == {"b": "ok", "a": "ok", "a2": "ok"}


def test_collect_all_only(monkeypatch):
    monkeypatch.setattr(collectors, "COLLECTORS", {"a": fake("a"), "b": fake("b")})
    packages, status = collectors.collect_all(["/r"], only=["b"])
    assert [p.ecosystem for p in packages] == ["b"]
    assert status == {"a": "skipped", "b": "ok"}


def test_collect_all_failed_and_absent(monkeypatch):
    monkeypatch.setattr(
        collectors, "COLLECTORS", {"a": lambda roots: None, "b": lambda roots: []}
    )
    assert collectors.collect_all(["/r"]) == ([], {"a": "failed", "b": "ok"})


def test_default_roots(monkeypatch):
    monkeypatch.setattr(collectors, "COLLECTORS", {"a": fake("a")})
    assert collectors.collect_all()[0][0].location == str(Path.home())


def test_collect_all_oserror_is_failed(monkeypatch, capsys):
    def boom(roots):
        raise PermissionError(13, "Permission denied", "/r/x")

    monkeypatch.setattr(collectors, "COLLECTORS", {"a": boom, "b": fake("b")})
    packages, status = collectors.collect_all(["/r"])
    assert packages == [Package("b", "x", "1", "/r")]
    assert status == {"a": "failed", "b": "ok"}
    assert "collector a: [Errno 13] Permission denied" in capsys.readouterr().err
