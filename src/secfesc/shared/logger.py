"""Shared logging system for secfesc tools."""

from __future__ import annotations

import logging
import sys
import threading
from pathlib import Path


def setup_logger(name: str = "secfesc", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        log_dir = Path.home() / ".config" / "secfesc"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "secfesc.log"

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    except (PermissionError, OSError):
        pass

    return logger


_logger: logging.Logger | None = None
_logger_lock = threading.Lock()


def get_logger() -> logging.Logger:
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                _logger = setup_logger()
    return _logger


def log_debug(message: str) -> None:
    get_logger().debug(message)


def log_info(message: str) -> None:
    get_logger().info(message)


def log_warning(message: str) -> None:
    get_logger().warning(message)


def log_error(message: str) -> None:
    get_logger().error(message)


def log_critical(message: str) -> None:
    get_logger().critical(message)
