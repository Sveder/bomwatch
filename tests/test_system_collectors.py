import pytest

from bomwatch.collectors import containers, system
from bomwatch.model import Package


def test_rpm_parse_and_collect(monkeypatch):
    out = "bash\t5.2.15-3.el9\tx86_64\nopenssl\t1:3.0.7-24.el9\tx86_64\nbad line\n"
    assert system.parse_rpm(out) == [
        Package("rpm", "bash", "5.2.15-3.el9", "x86_64", "rpm"),
        Package("rpm", "openssl", "1:3.0.7-24.el9", "x86_64", "rpm"),
    ]
    monkeypatch.setattr(system, "has", lambda tool: True)
    monkeypatch.setattr(system, "run", lambda cmd: out)
    assert len(system.collect_rpm([])) == 2
    monkeypatch.setattr(system, "run", lambda cmd: None)
    assert system.collect_rpm([]) is None
    monkeypatch.setattr(system, "has", lambda tool: False)
    assert system.collect_rpm([]) == []


def test_snap(monkeypatch):
    out = (
        "Name    Version   Rev    Tracking       Publisher   Notes\n"
        "core22  20240111  1122   latest/stable  canonical✓  base\n"
        "odd\n"
    )
    assert system.parse_snap(out) == [Package("snap", "core22", "20240111", "", "snap")]
    monkeypatch.setattr(system, "has", lambda tool: True)
    monkeypatch.setattr(system, "run", lambda cmd: out)
    assert len(system.collect_snap([])) == 1
    monkeypatch.setattr(system, "run", lambda cmd: None)
    assert system.collect_snap([]) is None
    monkeypatch.setattr(system, "has", lambda tool: False)
    assert system.collect_snap([]) == []


def test_flatpak(monkeypatch):
    out = (
        "Application ID\tVersion\tBranch\tInstallation\n"
        "org.godotengine.Godot\t4.3\tstable\tuser\n"
        "org.freedesktop.Platform\t\t23.08\tsystem\n"
        "short\tline\n"
    )
    assert system.parse_flatpak(out) == [
        Package("flatpak", "org.godotengine.Godot", "4.3", "user/stable", "flatpak"),
        Package(
            "flatpak", "org.freedesktop.Platform", "23.08", "system/23.08", "flatpak"
        ),
    ]
    monkeypatch.setattr(system, "has", lambda tool: True)
    monkeypatch.setattr(system, "run", lambda cmd: out)
    assert len(system.collect_flatpak([])) == 2
    monkeypatch.setattr(system, "run", lambda cmd: None)
    assert system.collect_flatpak([]) is None
    monkeypatch.setattr(system, "has", lambda tool: False)
    assert system.collect_flatpak([]) == []


def test_container_parse():
    out = "nginx\tlatest\tsha256:aa\n<none>\t<none>\tsha256:bb\nbad\n\t\t\n"
    assert containers.parse(out, "docker") == [
        Package("docker", "nginx", "sha256:aa", "latest", "docker"),
        Package("docker", "<none>@sha256:bb", "sha256:bb", "", "docker"),
    ]


@pytest.mark.parametrize(
    "func,engine",
    [
        (containers.collect_docker, "docker"),
        (containers.collect_podman, "podman"),
    ],
)
def test_container_collect(monkeypatch, func, engine):
    calls = []
    monkeypatch.setattr(containers, "has", lambda tool: True)
    monkeypatch.setattr(
        containers, "run", lambda cmd: calls.append(cmd) or "a\t1\tsha256:x\n"
    )
    assert func([])[0].ecosystem == engine
    assert calls[0][0] == engine
    monkeypatch.setattr(containers, "run", lambda cmd: None)
    assert func([]) is None
    monkeypatch.setattr(containers, "has", lambda tool: False)
    assert func([]) == []
