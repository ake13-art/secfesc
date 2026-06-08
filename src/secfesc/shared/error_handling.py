"""Shared error handling utilities."""

from __future__ import annotations

import functools
import subprocess
from typing import Any, Callable

from secfesc.shared.logger import log_debug

SUBPROCESS_TIMEOUT: int = 5


def handle_check_errors(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> dict[str, Any]:
        try:
            return func(*args, **kwargs)
        except (FileNotFoundError, PermissionError):
            return {"status": "info", "value": "not available"}
        except subprocess.TimeoutExpired:
            return {"status": "info", "value": "scan timeout"}
        except subprocess.CalledProcessError:
            return {"status": "info", "value": "check unavailable"}
        except Exception as e:
            log_debug(f"Unexpected error in {func.__name__}: {type(e).__name__}: {e}")
            return {"status": "info", "value": "check unavailable"}

    return wrapper


def safe_read_file(file_path: str, default: str | None = "not available") -> str | None:
    try:
        with open(file_path, "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return default
    except (UnicodeDecodeError, OSError):
        return default


def safe_subprocess_run(
    cmd: list, timeout: int = SUBPROCESS_TIMEOUT, default: str = ""
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, default, "timeout")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, -1, default, "command not found")
    except OSError as e:
        return subprocess.CompletedProcess(cmd, -1, default, f"error: {e}")


def sysctl_check(path: str, mapping: dict[str, tuple[str, str]]) -> dict[str, str]:
    val = safe_read_file(path, default=None)
    if val is not None and val in mapping:
        return {"status": mapping[val][0], "value": mapping[val][1]}
    return {"status": "info", "value": "not available"}
