from __future__ import annotations

from secfesc.shared.error_handling import handle_check_errors, sysctl_check
from secfesc.shared.registry import security_check

_RP_FILTER = {
    "1": ("ok", "Strict"),
    "2": ("warn", "Loose"),
    "0": ("bad", "Disabled"),
}


@security_check(name="Reverse Path Filter", category="network", risk="medium")
@handle_check_errors
def check() -> dict[str, str]:
    return sysctl_check("/proc/sys/net/ipv4/conf/all/rp_filter", _RP_FILTER)
