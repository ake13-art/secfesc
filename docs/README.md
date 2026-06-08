# secfesc Documentation

Linux security inspection and audit tools.

---

## Overview

**secfesc** combines two security tools:

| Tool | Purpose | Run as |
|------|---------|--------|
| **secfetch** | Quick security overview | User |
| **secscan** | Comprehensive audit | User or root |

```
secfetch          # Quick check
secfetch --short  # Compact output
secscan           # Basic audit (no root)
secscan --full    # Complete audit (requires root)
```

---

## Documentation

- [Installation](INSTALL.md) - Install secfesc
- [Configuration](CONFIG.md) - Configure checks
- [Usage](USAGE.md) - CLI reference
- [Architecture](ARCHITECTURE.md) - Project structure
- [Roadmap](../ROADMAP.md) - Development plans

---

## Quick Start

```bash
# Install
pip install secfesc

# Quick overview
secfetch

# Full audit
sudo secscan --full
```

---

## Getting Help

```bash
secfetch help           # List all checks
secfetch help <check>   # Check details
secscan --help          # Audit options
```
