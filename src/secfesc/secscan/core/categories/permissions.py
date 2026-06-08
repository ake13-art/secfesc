"""Critical file permission checks (category: permissions).

Uses ``os.stat`` only (metadata, not contents), so it works without root: a
non-privileged user can still see that, e.g., /etc/shadow is mis-permissioned.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check

_CAT = "permissions"


@dataclass(frozen=True)
class _Critical:
    path: str
    max_mode: int  # most permissive mode that is still acceptable
    severity: str
    check_id: str


CRITICAL_FILES = [
    _Critical("/etc/passwd", 0o644, "medium", "PERM-6210"),
    _Critical("/etc/group", 0o644, "medium", "PERM-6211"),
    _Critical("/etc/shadow", 0o640, "high", "PERM-6212"),
    _Critical("/etc/gshadow", 0o640, "high", "PERM-6213"),
]


@audit_check("permissions")
def check_permissions() -> list[AuditFinding]:
    findings: list[AuditFinding] = []

    for item in CRITICAL_FILES:
        if not os.path.exists(item.path):
            continue
        try:
            st = os.stat(item.path)
        except OSError:
            continue

        mode = st.st_mode & 0o777
        # Bits set in the actual mode that the allowed maximum does not permit.
        if mode & ~item.max_mode & 0o777:
            findings.append(AuditFinding.found(
                _CAT, item.check_id, f"{item.path} is too permissive", item.severity,
                f"{item.path} has mode {oct(mode)}; expected {oct(item.max_mode)} or stricter.",
                f"Tighten it: 'sudo chmod {oct(item.max_mode)[2:]} {item.path}'.",
                f"{item.path} {oct(mode)}",
            ))

        if st.st_uid != 0:
            findings.append(AuditFinding.found(
                _CAT, f"{item.check_id}-OWN", f"{item.path} is not owned by root", "high",
                f"{item.path} is owned by UID {st.st_uid}; critical files must be root-owned.",
                f"Fix ownership: 'sudo chown root:root {item.path}'.",
                f"{item.path} uid={st.st_uid}",
            ))

    return findings
