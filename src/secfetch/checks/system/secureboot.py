from __future__ import annotations

import glob
import os

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors


@security_check(name="Secure Boot", category="system", risk="high")
@handle_check_errors
def check() -> dict[str, str]:
    if not os.path.exists("/sys/firmware/efi"):
        return {"status": "warn", "value": "Not supported (Legacy BIOS)"}
    matches = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
    if not matches:
        return {"status": "warn", "value": "EFI var not readable"}
    with open(matches[0], "rb") as f:
        data = f.read()
    # UEFI variable format: 4-byte EFI attributes header + 1-byte value
    if len(data) >= 5:
        secureboot_value = data[4]
        if secureboot_value == 1:
            return {"status": "ok", "value": "Enabled"}
        if secureboot_value == 0:
            return {"status": "bad", "value": "Disabled"}
        return {"status": "warn", "value": f"Unexpected value: {secureboot_value}"}
    return {"status": "info", "value": "EFI var unreadable or malformed"}
