"""Authentication policy checks (category: authentication).

Parses ``/etc/login.defs`` (world-readable) and flags weak password-ageing,
password-hashing and umask defaults.
"""

from __future__ import annotations

from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check
from secfesc.shared.error_handling import safe_read_file

LOGIN_DEFS = "/etc/login.defs"
WEAK_HASHES = {"MD5", "DES", "SHA256", "BLOWFISH"}
_CAT = "authentication"


def _parse_login_defs(text: str) -> dict[str, str]:
    """Parse "KEY value" lines; first occurrence wins."""
    config: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key = parts[0].upper()
            if key not in config:
                config[key] = parts[1].strip()
    return config


def _as_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@audit_check("authentication")
def check_authentication() -> list[AuditFinding]:
    cfg = _parse_login_defs(safe_read_file(LOGIN_DEFS, default=""))
    if not cfg:
        return []

    findings: list[AuditFinding] = []

    # Maximum password age — 99999 (the default) effectively means "never expires".
    max_days = _as_int(cfg.get("PASS_MAX_DAYS", "99999"), 99999)
    if max_days > 365:
        findings.append(AuditFinding.found(
            _CAT, "AUTH-9230", "Password maximum age is high", "medium",
            f"PASS_MAX_DAYS is {max_days}; passwords effectively never need rotating.",
            "Set PASS_MAX_DAYS to 365 or less in /etc/login.defs.",
            f"PASS_MAX_DAYS {max_days}",
        ))

    # Minimum password age — 0 lets a user change a password repeatedly to bypass history.
    if _as_int(cfg.get("PASS_MIN_DAYS", "0"), 0) == 0:
        findings.append(AuditFinding.found(
            _CAT, "AUTH-9231", "No minimum password age", "low",
            "PASS_MIN_DAYS is 0, so passwords can be changed again immediately.",
            "Set PASS_MIN_DAYS to 1 or more in /etc/login.defs.",
            "PASS_MIN_DAYS 0",
        ))

    # Password expiry warning.
    warn_age = _as_int(cfg.get("PASS_WARN_AGE", "7"), 7)
    if warn_age < 7:
        findings.append(AuditFinding.found(
            _CAT, "AUTH-9232", "Password warning age is short", "low",
            f"PASS_WARN_AGE is {warn_age}; users get little warning before expiry.",
            "Set PASS_WARN_AGE to 7 or more in /etc/login.defs.",
            f"PASS_WARN_AGE {warn_age}",
        ))

    # Password hashing method.
    enc = cfg.get("ENCRYPT_METHOD", "").upper()
    if enc in WEAK_HASHES:
        findings.append(AuditFinding.found(
            _CAT, "AUTH-9234", "Weak password hashing method", "medium",
            f"ENCRYPT_METHOD is {enc}; modern hashes (SHA512 or YESCRYPT) are stronger.",
            "Set ENCRYPT_METHOD SHA512 (or YESCRYPT) in /etc/login.defs.",
            f"ENCRYPT_METHOD {enc}",
        ))

    # Default umask — anything weaker than 027 exposes new files to group/other.
    umask = cfg.get("UMASK")
    if umask:
        try:
            value = int(umask, 8)
        except ValueError:
            value = None
        if value is not None and (value & 0o027) != 0o027:
            findings.append(AuditFinding.found(
                _CAT, "AUTH-9328", "Weak default umask", "low",
                f"UMASK is {umask}; new files may be readable/writable by group or others.",
                "Set UMASK 027 (or stricter) in /etc/login.defs.",
                f"UMASK {umask}",
            ))

    return findings
