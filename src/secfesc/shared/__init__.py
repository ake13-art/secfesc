"""Shared utilities for secfesc tools."""

from secfesc.shared.colors import (
    BOLD,
    CLEAR,
    CYAN,
    GREEN,
    ICONS,
    RED,
    RESET,
    STATUS_COLORS,
    YELLOW,
    colorize,
)
from secfesc.shared.config import (
    CONFIG_PATH,
    DEFAULT_CONFIG,
    invalidate_cache,
    is_enabled,
    load_config,
)
from secfesc.shared.error_handling import (
    SUBPROCESS_TIMEOUT,
    handle_check_errors,
    safe_read_file,
    safe_subprocess_run,
    sysctl_check,
)
from secfesc.shared.logger import (
    get_logger,
    log_critical,
    log_debug,
    log_error,
    log_info,
    log_warning,
    setup_logger,
)
from secfesc.shared.scoring import WEIGHTS, calculate_score
from secfesc.shared.types import (
    CategoryAccumulator,
    CheckRegistration,
    CheckResult,
    FixItem,
    PortEntry,
)

__all__ = [
    "BOLD",
    "CLEAR",
    "CYAN",
    "GREEN",
    "RED",
    "RESET",
    "YELLOW",
    "colorize",
    "ICONS",
    "STATUS_COLORS",
    "CONFIG_PATH",
    "DEFAULT_CONFIG",
    "invalidate_cache",
    "is_enabled",
    "load_config",
    "SUBPROCESS_TIMEOUT",
    "handle_check_errors",
    "safe_read_file",
    "safe_subprocess_run",
    "sysctl_check",
    "get_logger",
    "log_critical",
    "log_debug",
    "log_error",
    "log_info",
    "log_warning",
    "setup_logger",
    "WEIGHTS",
    "calculate_score",
    "CategoryAccumulator",
    "CheckRegistration",
    "CheckResult",
    "FixItem",
    "PortEntry",
]
