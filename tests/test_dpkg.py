from bomwatch.collectors import dpkg
from bomwatch.model import Package

OUTPUT = (
    "ii \tbash\t5.2-1\tamd64\n"
    "rc \told-thing\t1.0\tamd64\n"
    "ii \tpython3\t3.12.3-0\tamd64\n"
    "garbage line\n"
)

STATES = (
    "hi \theld\t6.8\tamd64\n"
    "iU \tunpacked\t1.0\tamd64\n"
    "iF \thalf\t1.0\tamd64\n"
    "rc \tconfig-only\t1.0\tamd64\n"
    "un \tgone\t1.0\tamd64\n"
    "i\tshort\t1.0\tamd64\n"
)


def test_parse_keeps_installed_only():
    assert dpkg.parse(OUTPUT) == [
        Package("dpkg", "bash", "5.2-1", "amd64", "dpkg"),
        Package("dpkg", "python3", "3.12.3-0", "amd64", "dpkg"),
    ]


def test_parse_keeps_held_and_half_installed():
    assert [p.name for p in dpkg.parse(STATES)] == ["held", "unpacked", "half"]


def test_collect_uses_dpkg_query(monkeypatch):
    monkeypatch.setattr(dpkg, "has", lambda tool: True)
    monkeypatch.setattr(dpkg, "run", lambda cmd: OUTPUT)
    assert len(dpkg.collect([])) == 2


def test_collect_without_dpkg(monkeypatch):
    monkeypatch.setattr(dpkg, "has", lambda tool: False)
    assert dpkg.collect([]) == []


def test_collect_failing_dpkg_is_none(monkeypatch):
    monkeypatch.setattr(dpkg, "has", lambda tool: True)
    monkeypatch.setattr(dpkg, "run", lambda cmd: None)
    assert dpkg.collect([]) is None


def test_parse_records_source_package():
    out = "ii \tlibssl3\t3.0.14-1\tamd64\topenssl\nii \tbash\t5.2\tamd64\t\n"
    assert dpkg.parse(out) == [
        Package("dpkg", "libssl3", "3.0.14-1", "amd64", "openssl"),
        Package("dpkg", "bash", "5.2", "amd64", "dpkg"),
    ]
