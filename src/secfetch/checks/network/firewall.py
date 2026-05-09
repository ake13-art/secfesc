# checks/network/firewall.py
from __future__ import annotations

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors, safe_subprocess_run


def _ufw_rules() -> list[str] | None:
    # Parse ufw numbered rules. Returns None on timeout/error to distinguish from "no rules".
    result = safe_subprocess_run(["sudo", "ufw", "status", "numbered"], timeout=5)
    if result.returncode != 0:
        if "timeout" in result.stderr:
            return None  # Signal timeout separately from "no rules"
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("[")]


def _iptables_rules() -> list[str] | None:
    # Count non-default iptables rules (skip chain headers and empty lines)
    result = safe_subprocess_run(["sudo", "iptables", "-L", "-n"], timeout=5)
    if result.returncode != 0:
        if "timeout" in result.stderr:
            return None
        return []
    return [
        line
        for line in result.stdout.splitlines()
        if line.strip() and not line.startswith("Chain") and not line.startswith("target")
    ]


def _nft_rules() -> list[str] | None:
    # Count all non-empty, non-comment lines in the ruleset output
    result = safe_subprocess_run(["sudo", "nft", "list", "ruleset"], timeout=5)
    if result.returncode != 0:
        if "timeout" in result.stderr:
            return None
        return []
    return [
        line
        for line in result.stdout.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@security_check(
    name="Firewall Rules", category="network", risk="high"
)
@handle_check_errors
def check() -> dict[str, str]:
    # First check if ufw is enabled (most common on Ubuntu/Debian)
    result = safe_subprocess_run(["sudo", "ufw", "status"], timeout=5)
    if result.returncode == 0:
        status_line = result.stdout.split("\n")[0].strip()
        if "Status: active" in status_line:
            rules = _ufw_rules()
            if rules is None:
                return {"status": "info", "value": "ufw active: scan timeout"}
            return {"status": "ok", "value": f"ufw active: {len(rules)} rules"}
        # ufw installed but inactive – fall through to check nftables/iptables

    # Try other backends - check for any configured rules
    timed_out = False
    for name, fn in [
        ("nftables", _nft_rules),
        ("iptables", _iptables_rules),
    ]:
        rules = fn()
        if rules is None:
            timed_out = True
            continue
        if rules:
            return {"status": "ok", "value": f"{name}: {len(rules)} rules"}

    if timed_out:
        return {"status": "info", "value": "firewall scan timeout"}

    # No firewall found is "bad", not "warn" - this is a critical security issue
    return {"status": "bad", "value": "No active firewall found"}
