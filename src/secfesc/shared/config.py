"""Shared config loading for secfesc tools."""

from __future__ import annotations

import configparser
from pathlib import Path

CONFIG_PATH = Path.home() / ".config" / "secfesc" / "checks.conf"

DEFAULT_CONFIG = """
[checks]
aslr = true
secure_boot = true
kernel = true
lockdown = true
firewall_rules = true
open_ports = true
ptrace_scope = true
dmesg_restrict = true
tcp_syn_cookies = true
reverse_path_filter = true
lsm = false
kptr_restrict = false
modules_disabled = false
unprivileged_bpf = false
ipv6 = false
world_writable = false
suid_binaries = false
/tmp_noexec = false
/tmp_sticky_bit = false
services = false
"""

_config_cache: configparser.ConfigParser | None = None
_config_cache_key: str | None = None


def _cache_key() -> str:
    try:
        return str(CONFIG_PATH.resolve())
    except (OSError, RuntimeError):
        return str(CONFIG_PATH)


def invalidate_cache() -> None:
    global _config_cache, _config_cache_key
    _config_cache = None
    _config_cache_key = None


def load_config() -> configparser.ConfigParser:
    global _config_cache, _config_cache_key
    current_key = _cache_key()
    if _config_cache is not None and _config_cache_key == current_key:
        return _config_cache
    config = configparser.ConfigParser()
    if not CONFIG_PATH.exists():
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(DEFAULT_CONFIG.strip())
    config.read(CONFIG_PATH)
    _config_cache = config
    _config_cache_key = current_key
    return config


def is_enabled(config: configparser.ConfigParser, check_name: str) -> bool:
    return config.getboolean("checks", check_name, fallback=False)
