import pytest

from bomwatch import versions


@pytest.mark.parametrize(
    "eco,low,high",
    [
        ("dpkg", "1.0~rc1-1", "1.0-1"),
        ("dpkg", "1.0-1", "1.0-1+b1"),
        ("dpkg", "2.0", "1:0.1"),
        ("dpkg", "1.0+dfsg-1", "1.0.1-1"),
        ("dpkg", "7.88.1-10+deb12u5", "7.88.1-10+deb12u12"),
        ("dpkg", "1.0a", "1.0b"),
        ("rpm", "1.0~rc1-1", "1.0-1"),
        ("rpm", "1.0-1", "1.0^git1-1"),
        ("rpm", "1.0^git1-1", "1.0.1-1"),
        ("rpm", "1.0-1.el9", "1.0-2.el9"),
        ("rpm", "1.0a-1", "1.0.1-1"),
        ("rpm", "1.a", "1.b"),
        ("rpm", "1.9-1", "1:0.1-1"),
        ("rpm", "1.0-1", "1.0.0-1"),
        ("rpm", "1.0~a~b", "1.0~a"),
        ("pip", "1.0.dev1", "1.0a1"),
        ("pip", "1.0a1", "1.0b1"),
        ("pip", "1.0rc1", "1.0"),
        ("pip", "1.0", "1.0.post1"),
        ("pip", "1.0.post1.dev1", "1.0.post1"),
        ("pip", "1.0+local.1", "1.0+local.2"),
        ("pip", "1.0+abc", "1.0+1"),
        ("pip", "1!0.1", "2!0.0"),
        ("pip", "1.9", "1.10"),
        ("pip", "1.0-1", "1.0-2"),
        ("npm", "1.0.0-alpha", "1.0.0-alpha.1"),
        ("npm", "1.0.0-alpha.1", "1.0.0-alpha.beta"),
        ("npm", "1.0.0-rc.1", "1.0.0"),
        ("npm", "1.0.0+build.1", "1.0.1"),
        ("go", "v0.0.0-20240101-abcdef", "v0.1.0"),
        ("vscode", "1.2", "1.10"),
        ("npm", "not-semver", "not-semver2"),
        ("pip", "weird@1", "weird@2"),
        ("brew", "1.0rc1", "1.0"),
        ("brew", "1.0~x", "1.0-alpha"),
        ("brew", "1.0-alpha", "1.0-beta"),
        ("brew", "1.0", "1.0a"),
        ("brew", "1.0a", "1.0.1"),
        ("brew", "1.9", "1:0.1"),
    ],
)
def test_order(eco, low, high):
    assert versions.compare(eco, low, high) < 0
    assert versions.compare(eco, high, low) > 0


def test_equal_and_unordered():
    assert versions.compare("pip", "1.0", "1.0") == 0
    assert versions.compare("pip", "1.0", "1.0.0") == 0
    assert versions.compare("rpm", "1.0-1", "1.0-1.") == 0
    assert versions.compare("dpkg", "1.0", "01.0") == 0
    assert versions.compare("docker", "a", "b") is None
    assert versions.compare("pip", "", "1") is None


def test_deb_bad_epoch_is_zero():
    assert versions.compare_deb("x:1.0", "x:1.0") == 0
    assert versions.compare_deb("1.0", "0:1.0") == 0
    assert versions.compare_deb("-1", "1") != 0
