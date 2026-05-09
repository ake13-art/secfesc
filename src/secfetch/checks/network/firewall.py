# checks/network/firewall.py
from __future__ import annotations

import shutil

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors, safe_subprocess_run


def _ufw_status() -> bool:
    """Check if ufw is active. Works without sudo."""
    result = safe_subprocess_run(["ufw", "status"], timeout=3)
    if result.returncode == 0:
        return "Status: active" in result.stdout
    return False


def _ufw_rules() -> list[str] | None:
    """Parse ufw numbered rules. Returns None on timeout/error."""
    result = safe_subprocess_run(["ufw", "status", "numbered"], timeout=3)
    if result.returncode != 0:
        return None
    return [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("[")]


def _iptables_rules() -> list[str] | None:
    """Count non-default iptables rules. Try without sudo first."""
    permission_denied = False
    for cmd in (["iptables", "-L", "-n"], ["sudo", "iptables", "-L", "-n"]):
        if not shutil.which(cmd[0]):
            continue
        result = safe_subprocess_run(cmd, timeout=3)
        if result.returncode == 0:
            return [
                line
                for line in result.stdout.splitlines()
                if line.strip() and not line.startswith("Chain") and not line.startswith("target")
            ]
        if "timeout" in result.stderr:
            return None
        if "Permission denied" in result.stderr or "permission denied" in result.stderr:
            permission_denied = True
    if permission_denied:
        return None
    return []


def _nft_rules() -> list[str] | None:
    """Count nftables rules. Try without sudo first."""
    permission_denied = False
    for cmd in (["nft", "list", "ruleset"], ["sudo", "nft", "list", "ruleset"]):
        if not shutil.which(cmd[0]):
            continue
        result = safe_subprocess_run(cmd, timeout=3)
        if result.returncode == 0:
            return [
                line
                for line in result.stdout.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        if "timeout" in result.stderr:
            return None
        if "Permission denied" in result.stderr or "permission denied" in result.stderr:
            permission_denied = True
    if permission_denied:
        return None
    return []


@security_check(
    name="Firewall Rules", category="network", risk="high"
)
@handle_check_errors
def check() -> dict[str, str]:
    if shutil.which("ufw") and _ufw_status():
        rules = _ufw_rules()
        if rules is None:
            return {"status": "info", "value": "ufw active: scan timeout"}
        return {"status": "ok", "value": f"ufw active: {len(rules)} rules"}

    unable_to_check = False
    for name, fn in [
        ("nftables", _nft_rules),
        ("iptables", _iptables_rules),
    ]:
        rules = fn()
        if rules is None:
            unable_to_check = True
            continue
        if rules:
            return {"status": "ok", "value": f"{name}: {len(rules)} rules"}

    if unable_to_check:
        return {"status": "info", "value": "firewall status unreadable"}

    return {"status": "bad", "value": "No active firewall found"}
