"""Compare versions the way each ecosystem does.

``compare(ecosystem, a, b)`` returns a negative number, zero or a positive
number, like ``cmp``, or ``None`` when the two versions have no order (image
ids, an empty version). A diff reports an unordered change as ``changed``.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# ---------------------------------------------------------------- Debian


def _deb_order(char: str) -> int:
    """Weight of one character in dpkg's ``verrevcmp``."""
    if char == "~":
        return -1
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _deb_part(one: str, two: str) -> int:
    """Compare two upstream versions or two revisions like dpkg does."""
    i = j = 0
    while i < len(one) or j < len(two):
        first_diff = 0
        while (i < len(one) and not one[i].isdigit()) or (
            j < len(two) and not two[j].isdigit()
        ):
            left = _deb_order(one[i]) if i < len(one) else 0
            right = _deb_order(two[j]) if j < len(two) else 0
            if left != right:
                return left - right
            i, j = i + 1, j + 1
        while i < len(one) and one[i] == "0":
            i += 1
        while j < len(two) and two[j] == "0":
            j += 1
        while i < len(one) and one[i].isdigit() and j < len(two) and two[j].isdigit():
            if not first_diff:
                first_diff = ord(one[i]) - ord(two[j])
            i, j = i + 1, j + 1
        if i < len(one) and one[i].isdigit():
            return 1
        if j < len(two) and two[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _evr(version: str) -> tuple[int, str, str]:
    """Split ``epoch:upstream-revision``; a bad epoch counts as 0."""
    epoch, sep, rest = version.partition(":")
    if not sep or not epoch.isdigit():
        epoch, rest = "0", version
    upstream, _, revision = rest.rpartition("-")
    if not upstream:
        upstream, revision = rest, ""
    return int(epoch), upstream, revision


def compare_deb(one: str, two: str) -> int:
    """Compare two Debian versions (``dpkg --compare-versions``)."""
    left, right = _evr(one), _evr(two)
    if left[0] != right[0]:
        return left[0] - right[0]
    return _deb_part(left[1], right[1]) or _deb_part(left[2], right[2])


# ---------------------------------------------------------------- RPM


def _rpm_segments(text: str) -> list[str]:
    """Split an RPM version into digit runs, letter runs, ``~`` and ``^``."""
    return re.findall(r"~|\^|\d+|[a-zA-Z]+", text)


def rpmvercmp(one: str, two: str) -> int:
    """Compare two RPM version or release strings like ``rpmvercmp``."""
    left, right = _rpm_segments(one), _rpm_segments(two)
    while left or right:
        a = left[0] if left else None
        b = right[0] if right else None
        for mark in ("~", "^"):
            if mark in (a, b):
                if a == b:
                    break
                # ``~`` sorts before anything; ``^`` sorts after the end only.
                if mark == "~":
                    return -1 if a == "~" else 1
                if a == "^":
                    return 1 if b is None else -1
                return -1 if a is None else 1
        else:
            if a is None or b is None:
                return 1 if b is None else -1
            if a.isdigit() != b.isdigit():
                return 1 if a.isdigit() else -1
            if a.isdigit():
                a_int, b_int = int(a), int(b)
                if a_int != b_int:
                    return 1 if a_int > b_int else -1
            elif a != b:
                return 1 if a > b else -1
        left, right = left[1:], right[1:]
    return 0


def compare_rpm(one: str, two: str) -> int:
    """Compare two RPM ``[epoch:]version-release`` strings."""
    left, right = _evr(one), _evr(two)
    if left[0] != right[0]:
        return left[0] - right[0]
    return rpmvercmp(left[1], right[1]) or rpmvercmp(left[2], right[2])


# ---------------------------------------------------------------- PEP 440

_PEP440 = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>\d+)?)?
    (?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2}
_PRE_RANK.update(pre=2, preview=2)


def pep440_key(version: str) -> tuple | None:
    """Return a sort key for a PEP 440 version, or None if it is not one."""
    match = _PEP440.match(version)
    if not match:
        return None
    release = [int(p) for p in match["release"].split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = post = dev = None
    if match["pre_l"]:
        pre = (_PRE_RANK[match["pre_l"].lower()], int(match["pre_n"] or 0))
    if match["post_n1"] or match["post_l"]:
        post = int(match["post_n1"] or match["post_n2"] or 0)
    if match["dev_l"]:
        dev = int(match["dev_n"] or 0)
    if pre is None and post is None and dev is not None:
        pre_key: tuple = (-1,)
    elif pre is None:
        pre_key = (2,)
    else:
        pre_key = (1, *pre)
    local = tuple(
        (1, int(part), "") if part.isdigit() else (0, 0, part)
        for part in re.split(r"[-_.]", match["local"] or "")
        if part
    )
    return (
        int(match["epoch"] or 0),
        tuple(release),
        pre_key,
        (-1,) if post is None else (0, post),
        (1,) if dev is None else (0, dev),
        local,
    )


# ---------------------------------------------------------------- semver

_SEMVER = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def semver_key(version: str) -> tuple | None:
    """Return a sort key for a semver version (``v`` prefix allowed), or None."""
    match = _SEMVER.match(version.strip())
    if not match:
        return None
    core = tuple(int(match[i] or 0) for i in (1, 2, 3))
    if match[4] is None:
        return core, (1,)
    ids = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in match[4].split(".")
    )
    return core, (0, ids)


# ---------------------------------------------------------------- generic

_TILDE, _PRE, _END, _WORD, _NUM = range(5)
_PRE_WORDS = {
    "dev": 0,
    "snapshot": 0,
    "nightly": 0,
    "alpha": 1,
    "beta": 2,
    "pre": 3,
    "preview": 3,
    "rc": 4,
}


def generic_key(version: str) -> tuple:
    """Return a natural sort key where pre-release words sort before a release.

    ``1.0~x`` < ``1.0-alpha`` < ``1.0rc1`` < ``1.0`` < ``1.0a`` < ``1.0.1``;
    an epoch prefix (``2:``) wins over everything.
    """
    epoch, rest = 0, version
    match = re.match(r"(\d+):(.*)", version)
    if match:
        epoch, rest = int(match.group(1)), match.group(2)
    parts: list[tuple] = []
    for piece in re.findall(r"~|\d+|[a-zA-Z]+", rest):
        if piece == "~":
            parts.append((_TILDE, 0, ""))
        elif piece.isdigit():
            parts.append((_NUM, int(piece), ""))
        elif piece.lower() in _PRE_WORDS:
            parts.append((_PRE, _PRE_WORDS[piece.lower()], ""))
        else:
            parts.append((_WORD, 0, piece.lower()))
    parts.append((_END, 0, ""))
    return epoch, tuple(parts)


def _by_key(key: Callable[[str], tuple | None]) -> Callable[[str, str], int]:
    """Return a comparator from a key function, falling back to ``generic_key``."""

    def compare_keys(one: str, two: str) -> int:
        left, right = key(one), key(two)
        if left is None or right is None:
            left, right = generic_key(one), generic_key(two)
        return (left > right) - (left < right)

    return compare_keys


compare_pep440 = _by_key(pep440_key)
compare_semver = _by_key(semver_key)
compare_generic = _by_key(generic_key)

UNORDERED = frozenset(
    {
        "docker",
        "podman",
        "autostart",
        "credential",
        "mcp",
        "agent-config",
        "agent-memory",
    }
)
COMPARATORS: dict[str, Callable[[str, str], int]] = {
    "dpkg": compare_deb,
    "rpm": compare_rpm,
    "pip": compare_pep440,
    "npm": compare_semver,
    "npm-project": compare_semver,
    "cargo": compare_semver,
    "go": compare_semver,
    "vscode": compare_semver,
}


def compare(ecosystem: str, one: str, two: str) -> int | None:
    """Compare two versions of one ecosystem; None when they have no order."""
    if ecosystem in UNORDERED or not one or not two:
        return None
    if one == two:
        return 0
    return COMPARATORS.get(ecosystem, compare_generic)(one, two)
