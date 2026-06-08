"""SSH daemon hardening checks (category: ssh).

Reads the effective sshd configuration (``sshd -T`` when running as root,
falling back to parsing ``/etc/ssh/sshd_config``) and flags weak settings.
Directives that are absent fall back to OpenSSH's documented defaults, so an
unconfigured daemon is still judged correctly.
"""

from __future__ import annotations

import os

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_read_file, safe_subprocess_run

SSHD_CONFIG = "/etc/ssh/sshd_config"
_CAT = "ssh"


def _parse(text: str) -> dict[str, str]:
    """Parse "keyword value" lines; first occurrence wins, as sshd does."""
    config: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key = parts[0].lower()
        if key not in config:
            config[key] = parts[1].strip()
    return config


def _load_config() -> dict[str, str]:
    """Effective sshd config: prefer ``sshd -T`` (root), else the config file."""
    if os.geteuid() == 0:
        result = safe_subprocess_run(["sshd", "-T"], timeout=5)
        if result.returncode == 0 and result.stdout:
            parsed = _parse(result.stdout)
            if parsed:
                return parsed
    return _parse(safe_read_file(SSHD_CONFIG, default=""))


def _ssh_installed() -> bool:
    return os.path.exists(SSHD_CONFIG)


@audit_check("ssh")
def check_ssh() -> list[AuditFinding]:
    if not _ssh_installed():
        return []

    cfg = _load_config()
    findings: list[AuditFinding] = []

    # PermitRootLogin — modern OpenSSH defaults to "prohibit-password".
    permit_root = cfg.get("permitrootlogin", "prohibit-password").lower()
    if permit_root == "yes":
        findings.append(AuditFinding.found(
            _CAT, "SSH-7412", "Root login over SSH is permitted", "high",
            "PermitRootLogin is 'yes', allowing direct password-based root login over SSH.",
            "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
            "PermitRootLogin yes",
        ))
    elif permit_root in ("prohibit-password", "without-password", "forced-commands-only"):
        findings.append(AuditFinding.found(
            _CAT, "SSH-7413", "Root login allowed with keys", "low",
            f"PermitRootLogin is '{permit_root}'. Root may still log in using SSH keys.",
            "If root login is not required, set 'PermitRootLogin no'.",
            f"PermitRootLogin {permit_root}",
        ))

    # PermitEmptyPasswords — default "no".
    if cfg.get("permitemptypasswords", "no").lower() == "yes":
        findings.append(AuditFinding.found(
            _CAT, "SSH-7408", "Empty passwords accepted for SSH login", "high",
            "PermitEmptyPasswords is 'yes', letting accounts with no password log in over SSH.",
            "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
            "PermitEmptyPasswords yes",
        ))

    # PasswordAuthentication — default "yes"; key-based auth is preferred.
    if cfg.get("passwordauthentication", "yes").lower() == "yes":
        findings.append(AuditFinding.found(
            _CAT, "SSH-7414", "Password authentication enabled", "medium",
            "PasswordAuthentication is enabled; SSH passwords are brute-forceable.",
            "Use key-based authentication and set 'PasswordAuthentication no'.",
            "PasswordAuthentication yes",
        ))

    # Protocol 1 — long removed from OpenSSH but flag it if explicitly set.
    protocol = cfg.get("protocol", "")
    if "1" in [p.strip() for p in protocol.split(",") if p.strip()]:
        findings.append(AuditFinding.found(
            _CAT, "SSH-7401", "Legacy SSH protocol 1 enabled", "high",
            "SSH protocol version 1 is cryptographically broken.",
            "Remove the 'Protocol 1' directive; only protocol 2 should be used.",
            f"Protocol {protocol}",
        ))

    # X11Forwarding — default "no".
    if cfg.get("x11forwarding", "no").lower() == "yes":
        findings.append(AuditFinding.found(
            _CAT, "SSH-7468", "X11 forwarding enabled", "low",
            "X11Forwarding is enabled, widening the attack surface for connected clients.",
            "Disable it with 'X11Forwarding no' unless explicitly needed.",
            "X11Forwarding yes",
        ))

    # MaxAuthTries — default 6; lower values slow brute-force attempts.
    raw_tries = cfg.get("maxauthtries", "6")
    try:
        tries = int(raw_tries)
    except ValueError:
        tries = 6
    if tries > 4:
        findings.append(AuditFinding.found(
            _CAT, "SSH-7417", "MaxAuthTries is high", "low",
            f"MaxAuthTries is {tries}; a lower value limits brute-force attempts per connection.",
            "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config.",
            f"MaxAuthTries {tries}",
        ))

    return findings
