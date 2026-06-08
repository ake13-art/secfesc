"""User account checks (category: users).

Parses ``/etc/passwd`` (always readable) and, when running as root,
``/etc/shadow`` to flag accounts that weaken authentication.
"""

from __future__ import annotations

import os
from collections import Counter

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_read_file

_CAT = "users"


def _passwd_entries() -> list[list[str]]:
    """Return /etc/passwd rows split into fields (name:pw:uid:gid:gecos:home:shell)."""
    entries = []
    for line in safe_read_file("/etc/passwd", default="").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) >= 7:
            entries.append(fields)
    return entries


@audit_check("users")
def check_users() -> list[AuditFinding]:
    entries = _passwd_entries()
    findings: list[AuditFinding] = []

    # Accounts with UID 0 other than root.
    uid0 = [e[0] for e in entries if e[2] == "0" and e[0] != "root"]
    if uid0:
        findings.append(AuditFinding.found(
            _CAT, "USER-7201", "Non-root account(s) with UID 0", "high",
            "Accounts other than 'root' share UID 0 and therefore have full root privileges.",
            "Give each account a unique non-zero UID, or remove the extra UID 0 accounts.",
            ", ".join(uid0),
        ))

    # Duplicate UIDs.
    uid_counts = Counter(e[2] for e in entries)
    dup_uids = sorted(uid for uid, count in uid_counts.items() if count > 1)
    if dup_uids:
        findings.append(AuditFinding.found(
            _CAT, "USER-7202", "Duplicate UIDs in /etc/passwd", "medium",
            "Multiple accounts share the same UID, so they cannot be distinguished by the kernel.",
            "Assign each account a unique UID.",
            ", ".join(dup_uids),
        ))

    # Duplicate usernames.
    name_counts = Counter(e[0] for e in entries)
    dup_names = sorted(name for name, count in name_counts.items() if count > 1)
    if dup_names:
        findings.append(AuditFinding.found(
            _CAT, "USER-7203", "Duplicate usernames in /etc/passwd", "medium",
            "The same username appears more than once in /etc/passwd.",
            "Remove or rename the duplicate account entries.",
            ", ".join(dup_names),
        ))

    # Empty passwords (requires /etc/shadow, i.e. root).
    if os.geteuid() == 0:
        empty = []
        for line in safe_read_file("/etc/shadow", default="").splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[1] == "":
                empty.append(fields[0])
        if empty:
            findings.append(AuditFinding.found(
                _CAT, "USER-7204", "Account(s) with an empty password", "high",
                "These accounts have no password set and can be used to log in without credentials.",
                "Lock the accounts ('passwd -l <user>') or set a strong password.",
                ", ".join(empty),
            ))

    return findings
