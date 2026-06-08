"""Firewall checks (category: firewall).

Best-effort, non-interactive detection of an active firewall. Queries systemd
unit state (no root needed) for the common backends, plus ``ufw status`` and a
non-privileged ``nft list ruleset``. Reports a finding only when nothing
indicates an active firewall.
"""

from __future__ import annotations

import shutil

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_subprocess_run

FW_SERVICES = ["firewalld", "ufw", "nftables", "iptables", "ip6tables"]


def _active_services() -> list[str]:
    active = []
    for svc in FW_SERVICES:
        result = safe_subprocess_run(["systemctl", "is-active", svc], timeout=5)
        if result.returncode == 0 and result.stdout.strip() == "active":
            active.append(svc)
    return active


def _ufw_active() -> bool:
    result = safe_subprocess_run(["ufw", "status"], timeout=5)
    return result.returncode == 0 and "Status: active" in result.stdout


def _nft_has_ruleset() -> bool:
    result = safe_subprocess_run(["nft", "list", "ruleset"], timeout=5)
    if result.returncode != 0:
        return False
    return any(line.strip().startswith("table ") for line in result.stdout.splitlines())


@audit_check("firewall")
def check_firewall() -> list[AuditFinding]:
    # Without systemctl we can't reliably tell what's active; stay silent.
    if shutil.which("systemctl") is None:
        return []

    if _active_services() or _ufw_active() or _nft_has_ruleset():
        return []

    return [
        AuditFinding(
            category="firewall",
            check_id="FIRE-4513",
            title="No active firewall detected",
            severity="high",
            status="found",
            description=(
                "No active firewall backend (firewalld, ufw, nftables or iptables) "
                "was detected. Inbound traffic may be unfiltered."
            ),
            solution=(
                "Enable a firewall, e.g. 'sudo ufw enable' or "
                "'sudo systemctl enable --now firewalld'."
            ),
        )
    ]
