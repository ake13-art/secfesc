"""Group checks (category: groups).

Parses ``/etc/group`` (always readable) to flag inconsistencies and
unexpected membership of privileged groups.
"""

from __future__ import annotations

from collections import Counter

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_read_file

_CAT = "groups"


def _group_entries() -> list[list[str]]:
    """Return /etc/group rows split into fields (name:pw:gid:members)."""
    entries = []
    for line in safe_read_file("/etc/group", default="").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) >= 4:
            entries.append(fields)
    return entries


@audit_check("groups")
def check_groups() -> list[AuditFinding]:
    entries = _group_entries()
    findings: list[AuditFinding] = []

    # Duplicate GIDs.
    gid_counts = Counter(e[2] for e in entries)
    dup_gids = sorted(gid for gid, count in gid_counts.items() if count > 1)
    if dup_gids:
        findings.append(AuditFinding.found(
            _CAT, "GROUP-7301", "Duplicate GIDs in /etc/group", "medium",
            "Multiple groups share the same GID, so file ownership cannot be told apart.",
            "Assign each group a unique GID.",
            ", ".join(dup_gids),
        ))

    # Duplicate group names.
    name_counts = Counter(e[0] for e in entries)
    dup_names = sorted(name for name, count in name_counts.items() if count > 1)
    if dup_names:
        findings.append(AuditFinding.found(
            _CAT, "GROUP-7302", "Duplicate group names in /etc/group", "medium",
            "The same group name appears more than once in /etc/group.",
            "Remove or rename the duplicate group entries.",
            ", ".join(dup_names),
        ))

    # Extra members of the root group (GID 0).
    for entry in entries:
        if entry[2] == "0":
            members = [m for m in entry[3].split(",") if m and m != "root"]
            if members:
                findings.append(AuditFinding.found(
                    _CAT, "GROUP-7303", "Extra members in the root group", "medium",
                    "Accounts other than 'root' belong to the root group (GID 0), granting "
                    "elevated access to root-group-owned files.",
                    "Remove unnecessary members from the root group.",
                    ", ".join(members),
                ))

    return findings
