"""Who and what can log in or act as this user (OWASP ASI03).

Records name a credential and where it lives; the version is a short hash
of the secret, so a new or rotated key shows up as a change while the secret
itself never lands in a snapshot.

- SSH: ``authorized_keys`` entries (by SHA256 fingerprint) and private keys
  (flag ``unencrypted-key`` when the key has no passphrase).
- token stores: ``.npmrc``, ``.pypirc``, ``.netrc``, ``.git-credentials``,
  GitHub CLI hosts, AWS credentials, Docker logins and kube config.
- privilege: ``sudoers`` rules (flag ``nopasswd-all``) and login users of
  ``/etc/passwd`` (flag ``uid0`` for a second root).
"""

from __future__ import annotations

import base64
import binascii
import configparser
import hashlib
import re
import struct
from pathlib import Path

from bomwatch.collectors.common import digest, files_in, read_json, read_text, shorten
from bomwatch.model import Package

ECO = "credential"
KEY_TYPES = re.compile(r"^(ssh-|ecdsa-|sk-ssh-|sk-ecdsa-)")
NO_LOGIN = ("nologin", "false", "sync", "shutdown", "halt")


def record(name, secret, location, source, flags=""):
    """Return one credential record; ``secret`` is only kept as a hash."""
    return Package(ECO, name, digest(secret), str(location), source, flags)


# ---------------------------------------------------------------- SSH


def fingerprint(blob_b64: str) -> str | None:
    """Return the OpenSSH ``SHA256:`` fingerprint of a base64 key blob."""
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip(
        "="
    )


def parse_authorized_keys(text: str, location: Path) -> list[Package]:
    """Return one record per key; options such as ``command=`` are kept in source."""
    found = []
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts or parts[0].startswith("#"):
            continue
        index = next((i for i, p in enumerate(parts) if KEY_TYPES.match(p)), None)
        if index is None or index + 1 >= len(parts):
            continue
        key_type, blob = parts[index], parts[index + 1]
        print_ = fingerprint(blob)
        if print_ is None:
            continue
        comment = " ".join(parts[index + 2 :]) or "(no comment)"
        options = " ".join(parts[:index])
        found.append(
            Package(
                ECO,
                f"ssh-login {key_type} {comment}",
                print_,
                str(location),
                shorten(options) or "authorized_keys",
                "forced-command" if "command=" in options else "",
            )
        )
    return found


def key_is_encrypted(text: str) -> bool:
    """Return True when a PEM or OpenSSH private key is protected by a passphrase."""
    if "ENCRYPTED" in text:
        return True
    if "BEGIN OPENSSH PRIVATE KEY" not in text:
        return False
    body = "".join(
        line for line in text.splitlines() if line and not line.startswith("-----")
    )
    try:
        raw = base64.b64decode(body)
        magic = b"openssh-key-v1\0"
        (length,) = struct.unpack(">I", raw[len(magic) : len(magic) + 4])
        cipher = raw[len(magic) + 4 : len(magic) + 4 + length]
    except (binascii.Error, ValueError, struct.error):
        return False
    return cipher not in (b"none", b"")


def collect_ssh(home: Path) -> list[Package]:
    """Return authorized keys and private keys in ``~/.ssh``."""
    folder = home / ".ssh"
    found = []
    for name in ("authorized_keys", "authorized_keys2"):
        text = read_text(folder / name)
        if text is not None:
            found += parse_authorized_keys(text, folder / name)
    for path in files_in(folder):
        text = read_text(path)
        if text is None or "PRIVATE KEY-----" not in text:
            continue
        public = read_text(path.with_name(path.name + ".pub")) or ""
        parts = public.split()
        version = fingerprint(parts[1]) if len(parts) > 1 else None
        found.append(
            Package(
                ECO,
                f"ssh-key {path.name}",
                version or digest(text),
                str(folder),
                "private-key",
                "" if key_is_encrypted(text) else "unencrypted-key",
            )
        )
    return found


# ---------------------------------------------------------------- token stores


def npmrc(path: Path) -> list[Package]:
    """Return the registry tokens and passwords in an ``.npmrc``."""
    text = read_text(path) or ""
    found = []
    for line in text.splitlines():
        match = re.match(
            r"\s*(//[^:]*:)?(_authToken|_auth|_password)\s*=\s*(\S+)", line
        )
        if match:
            scope = (match[1] or "default").rstrip(":")
            found.append(record(f"npm {scope}", match[3], path, "npmrc"))
    return found


def ini_sections(path: Path, secret_keys, source: str, prefix: str) -> list[Package]:
    """Return one record per INI section that holds one of ``secret_keys``."""
    parser = configparser.RawConfigParser()
    try:
        parser.read_string(read_text(path) or "")
    except configparser.Error:
        return []
    found = []
    for section in parser.sections():
        secret = "".join(parser.get(section, k, fallback="") for k in secret_keys)
        if secret:
            found.append(record(f"{prefix} {section}", secret, path, source))
    return found


def netrc(path: Path) -> list[Package]:
    """Return one record per ``machine`` of a ``.netrc``."""
    words = (read_text(path) or "").split()
    found = []
    for i, word in enumerate(words):
        if word == "machine" and i + 1 < len(words):
            rest = words[i + 2 : i + 8]
            secret = rest[rest.index("password") + 1] if "password" in rest[:-1] else ""
            found.append(record(f"netrc {words[i + 1]}", secret, path, "netrc"))
    return found


def git_credentials(path: Path) -> list[Package]:
    """Return one record per stored URL, ``user@host``, of ``.git-credentials``."""
    found = []
    for line in (read_text(path) or "").splitlines():
        match = re.match(r"\s*\w+://([^:@/]+):([^@]+)@([^/\s]+)", line)
        if match:
            found.append(
                record(f"git {match[1]}@{match[3]}", match[2], path, "git-credentials")
            )
    return found


def gh_hosts(path: Path) -> list[Package]:
    """Return one record per host in the GitHub CLI ``hosts.yml``."""
    found: list[Package] = []
    host, token = None, ""

    def flush():
        if host:
            found.append(record(f"gh {host}", token, path, "gh-cli"))

    for line in (read_text(path) or "").splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            flush()
            host, token = line.rstrip()[:-1], ""
        elif "oauth_token:" in line:
            token += line.split(":", 1)[1].strip()
    flush()
    return found


def docker_auths(path: Path) -> list[Package]:
    """Return one record per registry login in a Docker ``config.json``."""
    data = read_json(path)
    auths = data.get("auths") if isinstance(data, dict) else None
    if not isinstance(auths, dict):
        return []
    return [
        record(f"docker {host}", str(value.get("auth", "")), path, "docker")
        for host, value in sorted(auths.items())
        if isinstance(value, dict) and value.get("auth")
    ]


def kube_users(path: Path) -> list[Package]:
    """Return a record for a kube config; any edit changes its version."""
    text = read_text(path)
    if text is None:
        return []
    users = re.findall(r"^-\s+name:\s*(\S+)", text.split("users:", 1)[-1], re.M)
    return [
        record(f"kube {', '.join(users[:5]) or 'config'}", text, path, "kubeconfig")
    ]


def collect_tokens(home: Path) -> list[Package]:
    """Return the tokens and passwords in the usual per-user stores."""
    return (
        npmrc(home / ".npmrc")
        + ini_sections(home / ".pypirc", ("password",), "pypirc", "pypi")
        + netrc(home / ".netrc")
        + netrc(home / "_netrc")
        + git_credentials(home / ".git-credentials")
        + gh_hosts(home / ".config" / "gh" / "hosts.yml")
        + ini_sections(
            home / ".aws" / "credentials",
            ("aws_access_key_id", "aws_secret_access_key"),
            "aws",
            "aws",
        )
        + docker_auths(home / ".docker" / "config.json")
        + kube_users(home / ".kube" / "config")
    )


# ---------------------------------------------------------------- privilege


def sudoers(etc: Path) -> list[Package]:
    """Return one record per rule in ``sudoers`` and ``sudoers.d``; unreadable
    files (they are root only) are skipped."""
    found = []
    for path in [etc / "sudoers", *files_in(etc / "sudoers.d")]:
        for raw in (read_text(path) or "").splitlines():
            line = " ".join(raw.split())
            if not line or line.startswith(("#", "Defaults")) or line.startswith("@"):
                continue
            flag = "nopasswd-all" if re.search(r"NOPASSWD:\s*ALL\b", line) else ""
            found.append(
                Package(
                    ECO, f"sudo {shorten(line, 200)}", "", str(path), "sudoers", flag
                )
            )
    return found


def login_users(etc: Path) -> list[Package]:
    """Return the users of ``/etc/passwd`` that have a login shell."""
    found = []
    for line in (read_text(etc / "passwd") or "").splitlines():
        parts = line.split(":")
        if len(parts) < 7 or parts[6].rsplit("/", 1)[-1] in NO_LOGIN:
            continue
        name, uid = parts[0], parts[2]
        flag = "uid0" if uid == "0" and name != "root" else ""
        found.append(
            Package(ECO, f"user {name}", uid, str(etc / "passwd"), parts[6], flag)
        )
    return found


def collect(_roots, home=None, etc=None):
    """Return the credentials and privileges of this machine and user."""
    home = Path.home() if home is None else Path(home)
    etc = Path("/etc") if etc is None else Path(etc)
    return collect_ssh(home) + collect_tokens(home) + sudoers(etc) + login_users(etc)
