from __future__ import annotations

import platform

from secfesc.shared.error_handling import handle_check_errors
from secfesc.shared.registry import security_check


@security_check(name="Kernel", category="system", risk="info")
@handle_check_errors
def check() -> dict[str, str]:
    return {"status": "info", "value": platform.release()}
