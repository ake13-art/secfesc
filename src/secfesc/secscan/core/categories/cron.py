"""Cron checks (category: cron).

Flags world-writable cron locations and an unrestricted cron policy. Uses
``os.stat`` only, so it works without root.
"""

from __future__ import annotations

import os

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check

CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]
CRON_DIRS = CRON_PATHS[1:]
_CAT = "cron"


def _is_world_writable(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & 0o002)
    except OSError:
        return False


@audit_check("cron")
def check_cron() -> list[AuditFinding]:
    findings: list[AuditFinding] = []

    # World-writable cron files/directories themselves.
    ww_paths = [p for p in CRON_PATHS if os.path.exists(p) and _is_world_writable(p)]
    if ww_paths:
        findings.append(AuditFinding.found(
            _CAT, "CRON-4001", "World-writable cron path(s)", "high",
            "Cron files or directories are world-writable; any user could schedule root jobs.",
            "Restrict permissions, e.g. 'sudo chmod o-w <path>'.",
            ", ".join(ww_paths),
        ))

    # World-writable entries inside the cron directories.
    ww_entries = []
    for directory in CRON_DIRS:
        if not os.path.isdir(directory):
            continue
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for entry in entries:
            full = os.path.join(directory, entry)
            if _is_world_writable(full):
                ww_entries.append(full)
    if ww_entries:
        findings.append(AuditFinding.found(
            _CAT, "CRON-4002", "World-writable files in cron directories", "high",
            "Files inside cron directories are world-writable and run with elevated privileges.",
            "Remove world-write permission: 'sudo chmod o-w <file>'.",
            ", ".join(ww_entries),
        ))

    # Neither cron.allow nor cron.deny — cron is open to every user.
    if not os.path.exists("/etc/cron.allow") and not os.path.exists("/etc/cron.deny"):
        findings.append(AuditFinding.found(
            _CAT, "CRON-4003", "Cron usage is not restricted", "low",
            "Neither /etc/cron.allow nor /etc/cron.deny exists; every user may use cron.",
            "Create /etc/cron.allow listing only the users permitted to use cron.",
        ))

    return findings
