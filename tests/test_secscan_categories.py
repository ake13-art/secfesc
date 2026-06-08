"""Tests for the v1.7 secscan categories: authentication, firewall, cron, permissions."""

import os
import subprocess
from unittest.mock import patch

import pytest


def _proc(returncode, stdout=""):
    return subprocess.CompletedProcess([], returncode, stdout, "")


# ── authentication ────────────────────────────────────────
class TestAuthentication:
    def _run(self, text, monkeypatch):
        from secfesc.secscan.core.categories import authentication

        monkeypatch.setattr(authentication, "safe_read_file", lambda *a, **k: text)
        return {f.check_id: f for f in authentication.check_authentication()}

    def test_high_max_age(self, monkeypatch):
        found = self._run("PASS_MAX_DAYS 99999\n", monkeypatch)
        assert found["AUTH-9230"].severity == "medium"

    def test_weak_hash(self, monkeypatch):
        found = self._run("PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nENCRYPT_METHOD MD5\n", monkeypatch)
        assert "AUTH-9234" in found
        assert "AUTH-9230" not in found  # 90 <= 365

    def test_weak_umask(self, monkeypatch):
        found = self._run("UMASK 022\n", monkeypatch)
        assert "AUTH-9328" in found

    def test_strong_config_is_clean(self, monkeypatch):
        text = (
            "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n"
            "ENCRYPT_METHOD SHA512\nUMASK 027\n"
        )
        assert self._run(text, monkeypatch) == {}

    def test_missing_login_defs(self, monkeypatch):
        assert self._run("", monkeypatch) == {}


# ── firewall ──────────────────────────────────────────────
class TestFirewall:
    def test_no_firewall_flagged(self, monkeypatch):
        from secfesc.secscan.core.categories import firewall

        monkeypatch.setattr(firewall.shutil, "which", lambda _: "/usr/bin/systemctl")
        monkeypatch.setattr(firewall, "safe_subprocess_run", lambda *a, **k: _proc(3, "inactive"))
        ids = {f.check_id for f in firewall.check_firewall()}
        assert "FIRE-4513" in ids

    def test_active_service_no_finding(self, monkeypatch):
        from secfesc.secscan.core.categories import firewall

        monkeypatch.setattr(firewall.shutil, "which", lambda _: "/usr/bin/systemctl")

        def run(cmd, **k):
            if cmd[:2] == ["systemctl", "is-active"] and cmd[2] == "firewalld":
                return _proc(0, "active")
            return _proc(3, "inactive")

        monkeypatch.setattr(firewall, "safe_subprocess_run", run)
        assert firewall.check_firewall() == []

    def test_no_systemctl_skips(self, monkeypatch):
        from secfesc.secscan.core.categories import firewall

        monkeypatch.setattr(firewall.shutil, "which", lambda _: None)
        assert firewall.check_firewall() == []


# ── cron ──────────────────────────────────────────────────
class TestCron:
    def test_world_writable_file_flagged(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import cron

        d = tmp_path / "cron.d"
        d.mkdir()
        job = d / "job"
        job.write_text("* * * * * root cmd")
        job.chmod(0o666)
        monkeypatch.setattr(cron, "CRON_PATHS", [str(d)])
        monkeypatch.setattr(cron, "CRON_DIRS", [str(d)])
        ids = {f.check_id for f in cron.check_cron()}
        assert "CRON-4002" in ids

    def test_clean_cron_dir(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import cron

        d = tmp_path / "cron.d"
        d.mkdir()
        job = d / "job"
        job.write_text("x")
        job.chmod(0o644)
        monkeypatch.setattr(cron, "CRON_PATHS", [str(d)])
        monkeypatch.setattr(cron, "CRON_DIRS", [str(d)])
        ids = {f.check_id for f in cron.check_cron()}
        assert "CRON-4001" not in ids
        assert "CRON-4002" not in ids


# ── permissions ───────────────────────────────────────────
class TestPermissions:
    def _crit(self, path):
        from secfesc.secscan.core.categories import permissions

        return permissions._Critical(str(path), 0o640, "high", "PERM-TEST")

    def test_too_permissive_flagged(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import permissions

        target = tmp_path / "shadow"
        target.write_text("x")
        target.chmod(0o644)  # world-readable -> exceeds 0o640
        monkeypatch.setattr(permissions, "CRITICAL_FILES", [self._crit(target)])
        ids = {f.check_id for f in permissions.check_permissions()}
        assert "PERM-TEST" in ids

    def test_strict_mode_ok_but_ownership_flagged(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import permissions

        target = tmp_path / "shadow"
        target.write_text("x")
        target.chmod(0o600)
        monkeypatch.setattr(permissions, "CRITICAL_FILES", [self._crit(target)])
        ids = {f.check_id for f in permissions.check_permissions()}
        assert "PERM-TEST" not in ids  # mode is acceptable
        if os.geteuid() != 0:
            assert "PERM-TEST-OWN" in ids  # tmp file not owned by root

    def test_missing_file_no_finding(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import permissions

        monkeypatch.setattr(
            permissions, "CRITICAL_FILES", [self._crit(tmp_path / "does-not-exist")]
        )
        assert permissions.check_permissions() == []


@pytest.mark.parametrize("module", ["authentication", "firewall", "cron", "permissions"])
def test_category_registered(module):
    """Each new category module registers at least one check."""
    import importlib

    from secfesc.secscan.core import registry

    registry._discovered = False
    registry._discover()
    cat = "authentication" if module == "authentication" else module
    importlib.import_module(f"secfesc.secscan.core.categories.{module}")
    assert registry.has_checks(cat)


# ── ssh additional branches ───────────────────────────────
class TestSSHAdditional:
    def _run(self, config_text):
        from secfesc.secscan.core.categories import ssh
        with patch.object(ssh, "_ssh_installed", return_value=True), \
             patch.object(ssh, "_load_config", return_value=ssh._parse(config_text)):
            return {f.check_id: f for f in ssh.check_ssh()}

    def test_parse_single_token_line_skipped(self):
        from secfesc.secscan.core.categories.ssh import _parse
        cfg = _parse("PermitRootLogin\nPasswordAuthentication yes\n")
        assert "passwordauthentication" in cfg
        assert "permitrootlogin" not in cfg

    def test_ssh_installed_returns_bool(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import ssh
        monkeypatch.setattr(ssh, "SSHD_CONFIG", str(tmp_path / "sshd_config"))
        assert ssh._ssh_installed() is False
        (tmp_path / "sshd_config").write_text("")
        assert ssh._ssh_installed() is True

    def test_load_config_as_root_uses_sshd_t(self, monkeypatch):
        from secfesc.secscan.core.categories import ssh
        monkeypatch.setattr(ssh.os, "geteuid", lambda: 0)
        result = subprocess.CompletedProcess([], 0, "PermitRootLogin no\n", "")
        monkeypatch.setattr(ssh, "safe_subprocess_run", lambda *a, **k: result)
        cfg = ssh._load_config()
        assert "permitrootlogin" in cfg

    def test_load_config_as_root_falls_back_on_sshd_t_failure(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import ssh
        monkeypatch.setattr(ssh.os, "geteuid", lambda: 0)
        fail = subprocess.CompletedProcess([], 1, "", "error")
        monkeypatch.setattr(ssh, "safe_subprocess_run", lambda *a, **k: fail)
        monkeypatch.setattr(ssh, "safe_read_file", lambda *a, **k: "PermitRootLogin no\n")
        cfg = ssh._load_config()
        assert "permitrootlogin" in cfg

    def test_x11forwarding_yes_flagged(self):
        found = self._run("X11Forwarding yes\n")
        assert "SSH-7468" in found

    def test_maxauthtries_invalid_value_defaults_to_6(self):
        found = self._run("MaxAuthTries bad_value\n")
        assert "SSH-7417" in found  # default 6 > 4 → flagged


# ── authentication additional branches ───────────────────
class TestAuthenticationAdditional:
    def _run(self, text, monkeypatch):
        from secfesc.secscan.core.categories import authentication
        monkeypatch.setattr(authentication, "safe_read_file", lambda *a, **k: text)
        return {f.check_id: f for f in authentication.check_authentication()}

    def test_comment_lines_ignored(self, monkeypatch):
        text = "# This is a comment\nPASS_MAX_DAYS 90\n"
        found = self._run(text, monkeypatch)
        assert "AUTH-9230" not in found

    def test_as_int_invalid_value_returns_default(self):
        from secfesc.secscan.core.categories.authentication import _as_int
        assert _as_int("not_a_number", 42) == 42
        assert _as_int(None, 99) == 99

    def test_warn_age_below_7_flagged(self, monkeypatch):
        found = self._run("PASS_WARN_AGE 3\n", monkeypatch)
        assert "AUTH-9232" in found

    def test_umask_invalid_octal_no_finding(self, monkeypatch):
        found = self._run("UMASK 0xBAD\n", monkeypatch)
        assert "AUTH-9328" not in found

    def test_umask_valid_strict_no_finding(self, monkeypatch):
        found = self._run("UMASK 027\n", monkeypatch)
        assert "AUTH-9328" not in found


# ── cron additional branches ─────────────────────────────
class TestCronAdditional:
    def test_is_world_writable_oserror_returns_false(self, monkeypatch):
        from secfesc.secscan.core.categories import cron
        monkeypatch.setattr(cron.os, "stat", lambda p: (_ for _ in ()).throw(OSError("no stat")))
        assert cron._is_world_writable("/some/path") is False

    def test_cron_path_itself_world_writable(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import cron
        f = tmp_path / "crontab"
        f.write_text("* * * * * root cmd")
        f.chmod(0o666)
        monkeypatch.setattr(cron, "CRON_PATHS", [str(f)])
        monkeypatch.setattr(cron, "CRON_DIRS", [])
        # prevent cron.allow check from producing extra findings
        monkeypatch.setattr(cron.os.path, "exists", lambda p: True)
        ids = {fi.check_id for fi in cron.check_cron()}
        assert "CRON-4001" in ids

    def test_nonexistent_dir_in_cron_dirs_skipped(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import cron
        monkeypatch.setattr(cron, "CRON_PATHS", [])
        # directory does not exist → isdir returns False → line 51 (continue) is hit
        monkeypatch.setattr(cron, "CRON_DIRS", [str(tmp_path / "no_such_dir")])
        monkeypatch.setattr(cron.os.path, "exists", lambda p: True)
        cron.check_cron()  # must not raise

    def test_dir_listing_oserror_skipped(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import cron
        d = tmp_path / "cron.d"
        d.mkdir()
        monkeypatch.setattr(cron, "CRON_PATHS", [])
        monkeypatch.setattr(cron, "CRON_DIRS", [str(d)])
        monkeypatch.setattr(cron.os, "listdir",
                            lambda p: (_ for _ in ()).throw(OSError("access denied")))
        monkeypatch.setattr(cron.os.path, "isdir", lambda p: True)
        monkeypatch.setattr(cron.os.path, "exists", lambda p: True)
        # Should not raise
        cron.check_cron()


# ── groups additional branches ────────────────────────────
class TestGroupsAdditional:
    def _run(self, text):
        from secfesc.secscan.core.categories import groups
        with patch.object(groups, "safe_read_file", return_value=text):
            return {f.check_id: f for f in groups.check_groups()}

    def test_comment_and_blank_lines_skipped(self):
        found = self._run("# comment\n\nroot:x:0:\n")
        assert "GROUP-7301" not in found

    def test_duplicate_names_flagged(self):
        found = self._run("admins:x:1000:\nadmins:x:1001:\n")
        assert "GROUP-7302" in found


# ── permissions additional branches ──────────────────────
class TestPermissionsAdditional:
    def test_stat_oserror_skipped(self, tmp_path, monkeypatch):
        from secfesc.secscan.core.categories import permissions
        target = tmp_path / "shadow"
        target.write_text("x")
        crit = permissions._Critical(str(target), 0o640, "high", "PERM-TEST")
        monkeypatch.setattr(permissions, "CRITICAL_FILES", [crit])
        # exists must return True so we reach os.stat; stat then raises → except OSError: continue
        monkeypatch.setattr(permissions.os.path, "exists", lambda p: True)
        monkeypatch.setattr(permissions.os, "stat",
                            lambda p: (_ for _ in ()).throw(OSError("no stat")))
        assert permissions.check_permissions() == []


# ── users additional branches ─────────────────────────────
class TestUsersAdditional:
    def _run(self, passwd, shadow="", is_root=False):
        from secfesc.secscan.core.categories import users

        def fake_read(path, default=""):
            if path == "/etc/passwd":
                return passwd
            if path == "/etc/shadow":
                return shadow
            return default

        with patch.object(users, "safe_read_file", side_effect=fake_read), \
             patch("secfesc.secscan.core.categories.users.os.geteuid",
                   return_value=0 if is_root else 1000):
            return {f.check_id: f for f in users.check_users()}

    def test_comment_and_blank_lines_skipped(self):
        passwd = "# comment\n\nroot:x:0:0::/root:/bin/bash\n"
        found = self._run(passwd)
        assert "USER-7201" not in found

    def test_duplicate_usernames_flagged(self):
        passwd = (
            "alice:x:1000:1000::/home/alice:/bin/bash\n"
            "alice:x:1001:1001::/home/alice2:/bin/bash\n"
        )
        found = self._run(passwd)
        assert "USER-7203" in found


# ── firewall (secscan) nft branch ────────────────────────
class TestSecScanFirewallAdditional:
    def test_nft_has_ruleset_returns_true(self, monkeypatch):
        from secfesc.secscan.core.categories import firewall
        monkeypatch.setattr(firewall.shutil, "which", lambda _: "/usr/bin/systemctl")

        def run(cmd, **k):
            if cmd[:2] == ["systemctl", "is-active"]:
                return subprocess.CompletedProcess([], 3, "inactive", "")
            if cmd == ["nft", "list", "ruleset"]:
                return subprocess.CompletedProcess([], 0, "table inet filter { }\n", "")
            return subprocess.CompletedProcess([], 3, "", "")

        monkeypatch.setattr(firewall, "safe_subprocess_run", run)
        assert firewall.check_firewall() == []
