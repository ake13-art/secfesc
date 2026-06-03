# Configuration

Config file: `~/.config/secfesc/checks.conf`

Created automatically on first run.

---

## Default Checks (secfetch)

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

---

## Available Check Keys

| Key | Description |
|-----|-------------|
| `aslr` | Address Space Layout Randomization |
| `secure_boot` | UEFI Secure Boot status |
| `kernel` | Kernel version |
| `lockdown` | Kernel lockdown mode |
| `firewall_rules` | Firewall status |
| `open_ports` | Listening network ports |
| `ptrace_scope` | Ptrace restrictions |
| `dmesg_restrict` | Dmesg access restrictions |
| `tcp_syn_cookies` | TCP SYN cookies |
| `reverse_path_filter` | Reverse path filtering |
| `lsm` | Linux Security Modules |
| `ipv6` | IPv6 status |
| `services` | Running services audit |

---

## Reloading Config

Restart secfetch to reload configuration.
