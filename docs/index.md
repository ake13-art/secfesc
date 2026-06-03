---
title: secfesc
description: Linux security inspection and audit tools — secfetch + secscan
---

# secfesc

**Linux security inspection and audit tools.** One package, two commands.

| Tool | Purpose | Run as |
|------|---------|--------|
| **secfetch** | Quick security overview ("neofetch for security") | User |
| **secscan** | Deep security audit (Lynis-style) | User or root |

---

## Install

```bash
pip install secfesc
```

See the [Installation guide](INSTALL.md) for details and alternatives.

---

## Quick start

```bash
secfetch              # Quick security overview
secfetch --short      # Compact box

secscan               # Basic audit (no root)
secscan --quick       # Essential checks
secscan --category ssh   # Audit a single category
sudo secscan --full   # Complete audit (requires root)
secscan --report json --output report.json   # Export findings
```

---

## What secscan checks (v1.6.0)

| Category | Checks |
|----------|--------|
| **SSH** | Root login, empty passwords, password authentication, legacy protocol 1, X11 forwarding, MaxAuthTries |
| **Users** | Non-root UID 0 accounts, empty passwords (root), duplicate UIDs/usernames |
| **Groups** | Duplicate GIDs/names, extra root-group members |

More categories are on the [roadmap](https://github.com/ake13-art/secfetch/blob/main/ROADMAP.md).

---

## Documentation

- [Installation](INSTALL.md) — install and update secfesc
- [Usage](USAGE.md) — full CLI reference for both tools
- [Configuration](CONFIG.md) — enable/disable checks
- [Architecture](ARCHITECTURE.md) — project structure and how to add checks
- [Roadmap](https://github.com/ake13-art/secfetch/blob/main/ROADMAP.md) — where secscan is heading
- [Changelog](https://github.com/ake13-art/secfetch/blob/main/CHANGELOG.md) — release history

---

## Getting help

```bash
secfetch help           # List all checks
secfetch help <check>   # Details for one check
secscan --help          # Audit options
```

---

<small>secfesc is licensed under the GNU General Public License v3.0.</small>
