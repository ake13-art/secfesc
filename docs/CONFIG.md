<div align="center">

```
   ________  _____/ __/__  __________
  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/
 (__  )  __/ /__/ __/  __(__  ) /__
/____/\___/\___/_/  \___/____/\___/
```

[← README](../README.md) · [Installation](INSTALL.md) · [Usage](USAGE.md) · [Architecture](ARCHITECTURE.md)

# Configuration

*Enable and disable checks. Choose your startup logo.*

</div>

---

## Config file

```
~/.config/secfesc/checks.conf
```

Created automatically on first run with all defaults. Edit it at any time — restart secfetch to reload.

---

## Display settings

Controls how `secfetch --short` looks.

```ini
[display]
logo = secfesc
```

### Built-in logos

| Value | Distro / Style |
|-------|----------------|
| `secfesc` | secfesc ASCII art (default) |
| `arch` | Arch Linux |
| `debian` | Debian |
| `ubuntu` | Ubuntu |
| `fedora` | Fedora |
| `none` | No logo — info only |

> [!TIP]
> Put `secfetch --short` at the end of your `~/.bashrc` or `~/.zshrc` and set `logo` to match your distro. You get your security status every time you open a terminal — just like fastfetch shows system info.

See [Usage → Startup integration](USAGE.md#startup-integration) for the full setup guide.

---

## Check settings

Controls which checks `secfetch` and `secfetch fastscan` run.

```ini
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

# Disabled by default (fullscan only)
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
```

### All available keys

| Key | Default | Description |
|-----|---------|-------------|
| `aslr` | `true` | Address Space Layout Randomization |
| `secure_boot` | `true` | UEFI Secure Boot status |
| `kernel` | `true` | Kernel version |
| `lockdown` | `true` | Kernel lockdown mode |
| `firewall_rules` | `true` | Firewall status (firewalld / ufw / nft / iptables) |
| `open_ports` | `true` | Listening network ports |
| `ptrace_scope` | `true` | Ptrace process-tracing restrictions |
| `dmesg_restrict` | `true` | Dmesg access restrictions |
| `tcp_syn_cookies` | `true` | TCP SYN cookie flood protection |
| `reverse_path_filter` | `true` | Reverse path filtering (anti-spoofing) |
| `lsm` | `false` | Linux Security Modules (AppArmor / SELinux) |
| `kptr_restrict` | `false` | Kernel pointer exposure |
| `modules_disabled` | `false` | Runtime kernel module loading |
| `unprivileged_bpf` | `false` | Unprivileged BPF access |
| `ipv6` | `false` | IPv6 status |
| `services` | `false` | Running services audit (blacklist-based) |
| `world_writable` | `false` | World-writable files (slow, full FS scan) |
| `suid_binaries` | `false` | SUID binary audit (slow, full FS scan) |
| `/tmp_noexec` | `false` | /tmp mounted with noexec |
| `/tmp_sticky_bit` | `false` | Sticky bit on /tmp |

> [!NOTE]
> `fastscan` only runs checks marked `true`. A plain `secfetch` (no flag) always runs all enabled checks regardless of fastscan status.

---

<div align="center">

[← README](../README.md) · [Installation](INSTALL.md) · [Usage](USAGE.md) · [Architecture](ARCHITECTURE.md)

</div>
