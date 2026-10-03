import base64
import json
import struct

from bomwatch.collectors import credentials
from bomwatch.collectors.common import digest
from bomwatch.model import Package

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
FINGERPRINT = credentials.fingerprint(BLOB)


def openssh_key(cipher: bytes) -> str:
    raw = b"openssh-key-v1\0" + struct.pack(">I", len(cipher)) + cipher + b"rest"
    body = base64.b64encode(raw).decode()
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"


def test_fingerprint():
    assert FINGERPRINT.startswith("SHA256:") and "=" not in FINGERPRINT
    assert credentials.fingerprint("not base64!") is None


def test_authorized_keys(tmp_path):
    text = (
        "# comment\n"
        f"ssh-ed25519 {BLOB} me@laptop\n"
        f'command="/usr/bin/backup",no-pty ssh-ed25519 {BLOB}\n'
        "ssh-rsa\n"
        "ssh-rsa !!!bad!!! x\n"
        "garbage line\n"
    )
    found = credentials.parse_authorized_keys(text, tmp_path / "authorized_keys")
    assert found == [
        Package(
            "credential",
            "ssh-login ssh-ed25519 me@laptop",
            FINGERPRINT,
            str(tmp_path / "authorized_keys"),
            "authorized_keys",
        ),
        Package(
            "credential",
            "ssh-login ssh-ed25519 (no comment)",
            FINGERPRINT,
            str(tmp_path / "authorized_keys"),
            'command="/usr/bin/backup",no-pty',
            "forced-command",
        ),
    ]


def test_key_encryption():
    assert not credentials.key_is_encrypted(openssh_key(b"none"))
    assert credentials.key_is_encrypted(openssh_key(b"aes256-ctr"))
    assert credentials.key_is_encrypted("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
    assert not credentials.key_is_encrypted("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n")
    broken = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n@@@@\n-----END OPENSSH PRIVATE KEY-----"
    )
    assert not credentials.key_is_encrypted(broken)


def test_collect_ssh(tmp_path):
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    (ssh / "authorized_keys").write_text(f"ssh-ed25519 {BLOB} a@b\n")
    (ssh / "id_ed25519").write_text(openssh_key(b"none"))
    (ssh / "id_ed25519.pub").write_text(f"ssh-ed25519 {BLOB} me\n")
    (ssh / "deploy").write_text(openssh_key(b"aes256-ctr"))
    (ssh / "known_hosts").write_text("host ssh-ed25519 AAAA\n")
    found = credentials.collect_ssh(tmp_path)
    assert [(p.name, p.version == FINGERPRINT, p.flags) for p in found] == [
        ("ssh-login ssh-ed25519 a@b", True, ""),
        ("ssh-key deploy", False, ""),
        ("ssh-key id_ed25519", True, "unencrypted-key"),
    ]


def test_token_stores(tmp_path):
    (tmp_path / ".npmrc").write_text(
        "//registry.npmjs.org/:_authToken=npm_SECRET\n_auth=abc\nregistry=https://x\n"
    )
    (tmp_path / ".pypirc").write_text(
        "[pypi]\nusername=__token__\npassword=pypi-SECRET\n[testpypi]\n"
    )
    (tmp_path / ".netrc").write_text(
        "machine api.x.com login me password hunter2\nmachine y.com login u\n"
    )
    (tmp_path / ".git-credentials").write_text(
        "https://me:ghp_SECRET@github.com\nbad\n"
    )
    (tmp_path / ".config" / "gh").mkdir(parents=True)
    (tmp_path / ".config" / "gh" / "hosts.yml").write_text(
        "github.com:\n    oauth_token: gho_SECRET\n    user: me\nghe.corp:\n    user: me\n"
    )
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text(
        "[default]\naws_access_key_id=AKIA\naws_secret_access_key=SECRET\n"
    )
    (tmp_path / ".docker").mkdir()
    (tmp_path / ".docker" / "config.json").write_text(
        json.dumps({"auths": {"ghcr.io": {"auth": "c2VjcmV0"}, "empty.io": {}}})
    )
    (tmp_path / ".kube").mkdir()
    (tmp_path / ".kube" / "config").write_text("users:\n- name: admin\n  user: {}\n")
    found = credentials.collect_tokens(tmp_path)
    assert [p.name for p in found] == [
        "npm //registry.npmjs.org/",
        "npm default",
        "pypi pypi",
        "netrc api.x.com",
        "netrc y.com",
        "git me@github.com",
        "gh github.com",
        "gh ghe.corp",
        "aws default",
        "docker ghcr.io",
        "kube admin",
    ]
    assert found[0].version == digest("npm_SECRET")
    text = json.dumps([p.to_dict() for p in found])
    for secret in (
        "npm_SECRET",
        "pypi-SECRET",
        "hunter2",
        "ghp_SECRET",
        "gho_SECRET",
        "c2VjcmV0",
    ):
        assert secret not in text


def test_token_store_edge_cases(tmp_path):
    (tmp_path / ".pypirc").write_text("not = an ini [\n")
    (tmp_path / ".docker").mkdir()
    (tmp_path / ".docker" / "config.json").write_text("[]")
    assert (
        credentials.ini_sections(tmp_path / ".pypirc", ("password",), "pypirc", "pypi")
        == []
    )
    assert credentials.docker_auths(tmp_path / ".docker" / "config.json") == []
    assert not credentials.kube_users(tmp_path / "missing")


def test_sudoers_and_users(tmp_path):
    (tmp_path / "sudoers").write_text(
        "Defaults env_reset\n# c\n@includedir /etc/sudoers.d\nroot ALL=(ALL:ALL) ALL\n"
    )
    (tmp_path / "sudoers.d").mkdir()
    (tmp_path / "sudoers.d" / "agent").write_text("agent ALL=(ALL) NOPASSWD: ALL\n")
    (tmp_path / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
        "toor:x:0:0::/root:/bin/sh\n"
        "short:x\n"
    )
    found = credentials.collect([], home=tmp_path / "home", etc=tmp_path)
    assert [(p.name, p.flags) for p in found] == [
        ("sudo root ALL=(ALL:ALL) ALL", ""),
        ("sudo agent ALL=(ALL) NOPASSWD: ALL", "nopasswd-all"),
        ("user root", ""),
        ("user toor", "uid0"),
    ]
