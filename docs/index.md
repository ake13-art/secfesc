---
title: secfesc
description: Linux security inspection and audit tools — secfetch + secscan
---

<div align="center">

```
                   ____
   ________  _____/ __/__  __________
  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/
 (__  )  __/ /__/ __/  __(__  ) /__
/____/\___/\___/_/  \___/____/\___/
```

**Linux security inspection and audit tools.**

![Version](https://img.shields.io/badge/version-1.7.0-1f6feb?style=flat-square&labelColor=0d1117)
![License](https://img.shields.io/badge/license-GPL--3.0-58a6ff?style=flat-square&labelColor=0d1117)
![Python](https://img.shields.io/badge/python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white&labelColor=0d1117)

</div>

---

## Two tools, one purpose

| Tool | Purpose | Run as |
|------|---------|--------|
| **secfetch** | Quick security overview | User |
| **secscan** | Deep security audit (Lynis-style) | User or root |

---

## Install

```bash
pipx install secfesc
```

See the [Installation guide](INSTALL.md) for alternatives and startup integration.

---

## Quick start

```bash
secfetch               # Full security overview
secfetch --short       # Compact fastfetch-style summary

secscan                # Basic audit (no root)
secscan --quick        # Essential checks only
secscan --category ssh # Audit a single category
sudo secscan --full    # Complete audit (requires root)

secscan --report json --output report.json   # Export findings
```

---

## What secscan checks (v1.7.0)

| Category | Key checks |
|----------|------------|
| **SSH** | Root login, empty passwords, password auth, legacy protocol, X11 forwarding, MaxAuthTries |
| **Users** | Non-root UID 0 accounts, empty passwords (root), duplicate UIDs/names |
| **Groups** | Duplicate GIDs/names, extra root-group members |
| **Authentication** | Password ageing policy, weak hash method, UMASK (`/etc/login.defs`) |
| **Firewall** | Active firewall detection (firewalld / ufw / nftables / iptables) |
| **Cron** | World-writable cron paths/files, unrestricted cron policy |
| **Permissions** | Mode & ownership of `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` |

More categories are on the [roadmap](../ROADMAP.md).

---

## Documentation

| Document | What it covers |
|----------|----------------|
| [Installation](INSTALL.md) | Install, update, startup integration |
| [Usage](USAGE.md) | Full CLI reference for both tools |
| [Configuration](CONFIG.md) | Enable/disable checks, choose your startup logo |
| [Architecture](ARCHITECTURE.md) | Project structure, how to add checks and logos |
| [Roadmap](../ROADMAP.md) | Where secscan is heading |
| [Changelog](../CHANGELOG.md) | Release history |

---

## Getting help

```bash
secfetch help           # List all secfetch checks
secfetch help <check>   # Details and fix hints for one check
secscan --help          # secscan audit options
```

---

<small>secfesc is licensed under the GNU General Public License v3.0.</small>
