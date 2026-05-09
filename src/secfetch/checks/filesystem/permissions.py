"""Filesystem permission security checks."""
import os
import stat
import subprocess
from pathlib import Path

from secfetch.core.check import security_check
from secfetch.core.error_handling import handle_check_errors

_SAFE_SUID_PATHS: frozenset[str] = frozenset({
    "/usr/bin/sudo", "/bin/su", "/usr/bin/su",
    "/usr/bin/passwd", "/usr/bin/gpasswd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/expiry",
    "/bin/mount", "/usr/bin/mount", "/bin/umount", "/usr/bin/umount",
    "/bin/ping", "/usr/bin/ping", "/bin/ping6", "/usr/bin/ping6",
    "/usr/bin/pkexec", "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
})
_SAFE_SUID_NAMES: frozenset[str] = frozenset(os.path.basename(p) for p in _SAFE_SUID_PATHS)

_SKIPPED_DIRS = (
    "/proc", "/sys", "/dev", "/tmp", "/var/tmp", "/run", "/var/run",
    "/snap", "/var/lib/docker", "/var/lib/lxc", "/var/lib/containerd",
    "/var/cache", "/var/lib/apt", "/var/lib/dpkg",
)

# Shared cache for single filesystem traversal
_fs_scan_cache: dict[str, list[str]] | None = None


def _build_find_cmd() -> list[str]:
    """Build a find command that prunes known-safe dirs and finds world-writable OR suid files."""
    prune_expr = ["("]
    for i, d in enumerate(_SKIPPED_DIRS):
        if i:
            prune_expr.append("-o")
        prune_expr.extend(["-path", f"{d}", "-o", "-path", f"{d}/*"])
    prune_expr.append(")")
    return [
        "find", "/", "-xdev", *prune_expr, "-prune", "-o",
        "-type", "f", "(", "-perm", "-002", "-o", "-perm", "-4000", ")",
        "-printf", "%m %p\n",
    ]


def _scan_filesystem() -> tuple[list[str], list[str]]:
    """Run a single find traversal and return (world_writable_files, suid_files)."""
    global _fs_scan_cache
    if _fs_scan_cache is not None:
        return (_fs_scan_cache["ww"], _fs_scan_cache["suid"])

    cmd = _build_find_cmd()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stderr=subprocess.DEVNULL)

    ww_files: list[str] = []
    suid_files: list[str] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.strip().split(" ", 1)
        if len(parts) != 2:
            continue
        perm_str, path = parts
        try:
            perm = int(perm_str, 8)
        except ValueError:
            continue
        if perm & stat.S_ISUID:
            suid_files.append(path)
        if perm & stat.S_IWOTH:
            ww_files.append(path)

    _fs_scan_cache = {"ww": ww_files, "suid": suid_files}
    return ww_files, suid_files


@security_check(name="World Writable", category="filesystem", risk="high")
@handle_check_errors
def world_writable() -> dict[str, str]:
    """Find world-writable files outside of expected locations."""
    files, _ = _scan_filesystem()

    if not files:
        return {"status": "ok", "value": "No unexpected world-writable files"}
    elif len(files) <= 5:
        return {"status": "warn", "value": f"{len(files)} world-writable files found"}
    else:
        return {"status": "bad", "value": f"{len(files)} world-writable files found"}


@security_check(name="SUID Binaries", category="filesystem", risk="medium")
@handle_check_errors
def suid_binaries() -> dict[str, str]:
    """Find SUID binaries that could be privilege escalation vectors."""
    _, suid_files = _scan_filesystem()

    total = 0
    unexpected = []

    for path in suid_files:
        total += 1
        if path not in _SAFE_SUID_PATHS and os.path.basename(path) not in _SAFE_SUID_NAMES:
            unexpected.append(path)

    unexpected_count = len(unexpected)

    if unexpected_count == 0:
        return {"status": "ok", "value": f"{total} SUID binaries (all expected)"}
    elif unexpected_count <= 3:
        return {"status": "warn", "value": f"{unexpected_count} unexpected SUID binaries"}
    else:
        return {"status": "bad", "value": f"{unexpected_count} unexpected SUID binaries"}


@security_check(name="/tmp noexec", category="filesystem", risk="medium")
@handle_check_errors
def tmp_noexec() -> dict[str, str]:
    """Check if /tmp is mounted with noexec option."""
    with open("/proc/mounts", "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 4 and parts[1] == "/tmp":
                mount_options = parts[3]
                if "noexec" in mount_options.split(","):
                    return {"status": "ok", "value": "/tmp mounted with noexec"}
                else:
                    return {"status": "bad", "value": "/tmp allows execution"}

    return {"status": "warn", "value": "/tmp not separately mounted"}


@security_check(name="/tmp Sticky Bit", category="filesystem", risk="low")
@handle_check_errors
def sticky_tmp() -> dict[str, str]:
    """Check if /tmp has the sticky bit set."""
    tmp_path = Path("/tmp")
    try:
        # Use lstat() to avoid following symlinks (TOCTOU protection)
        mode = tmp_path.lstat().st_mode
    except OSError:
        return {"status": "warn", "value": "/tmp directory does not exist"}

    if mode & stat.S_ISVTX:
        return {"status": "ok", "value": "/tmp has sticky bit set"}
    else:
        return {"status": "bad", "value": "/tmp missing sticky bit"}
