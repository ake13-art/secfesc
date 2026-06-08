<div align="center">

```
   ________  _____/ __/__  __________
  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/
 (__  )  __/ /__/ __/  __(__  ) /__
/____/\___/\___/_/  \___/____/\___/
```

[← README](../README.md) · [Installation](INSTALL.md) · [Configuration](CONFIG.md) · [Architecture](ARCHITECTURE.md)

# Usage

*Full CLI reference for secfetch and secscan.*

</div>

---

## secfetch

Quick security overview.

| Command | Description |
|---------|-------------|
| `secfetch` | Full security overview |
| `secfetch --short` | Compact fastfetch-style summary |
| `secfetch fastscan` | Fast scan (enabled checks only) |
| `secfetch fastscan --short` | Fast scan, compact output |
| `secfetch live` | Live monitoring, auto-refresh every 5 s |
| `secfetch live --interval N` | Live monitoring, refresh every N seconds |
| `secfetch improve` | Show failing checks with fix suggestions |
| `secfetch improve --auto` | Interactive auto-fix selection and apply |
| `secfetch help` | List all checks |
| `secfetch help <name>` | Detailed info about a specific check |

Which checks run is controlled by `~/.config/secfesc/checks.conf`.

---

## secscan

Comprehensive security audit.

| Command | Description |
|---------|-------------|
| `secscan` | Basic audit (no root needed) |
| `secscan --full` | Complete audit (more categories with root) |
| `secscan --quick` | Essential checks only |
| `secscan --category <name>` | Audit a single category (e.g. `ssh`, `cron`) |
| `secscan --report json` | Export results to stdout — clean, machine-readable |
| `secscan --report html --output report.html` | Export report to file |
| `secscan --report csv` | CSV export to stdout |
| `secscan --verbose` | Enable verbose / debug output |
| `secscan --quiet` | Suppress human summary |

> [!NOTE]
> When `--report` writes to stdout (no `--output`), the human summary is suppressed so the JSON/CSV/HTML stream stays clean and pipeable.

---

## Startup integration

`secfetch --short` is designed to run at terminal startup — a fastfetch-style security greeting.

**Setup:**

```bash
# Add to ~/.bashrc or ~/.zshrc
secfetch --short
```

**Choose a logo** in `~/.config/secfesc/checks.conf`:

```ini
[display]
logo = arch
```

Available logos: `secfesc` (default) · `arch` · `debian` · `ubuntu` · `fedora` · `none`

```
      /\            max@myhost
     /  \           ──────────
    / /\ \          Kernel       6.14.6-zen1-1-zen
   / /  \ \         Secure Boot  ✔ Enabled
  /_/    \_\        ASLR         ✔ Full
                    Lockdown     ✔ integrity
                    Firewall     ✔ firewalld active
                    Ports        ✔ 22, 53
                    Score        [████████████]  92/100
```

> [!TIP]
> Use `logo = none` for a minimal info-only view with no ASCII art.

---

## Exit codes (secscan)

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Warnings found (medium severity) |
| `2` | Errors found (high severity) |
| `3` | Fatal error |
| `130` | Interrupted (Ctrl+C) |

secscan is CI-friendly: a non-zero exit signals something needs attention.

```bash
secscan --quick && echo "All clear"
```

---

## Examples

**Daily check at a glance**

```bash
secfetch --short
```

**Weekly deep audit**

```bash
sudo secscan --full
```

**Export a report**

```bash
secscan --report html --output audit.html
```

**Audit only SSH configuration**

```bash
secscan --category ssh
```

**Pipe JSON findings to jq**

```bash
secscan --report json | jq '.findings[] | select(.severity == "high")'
```

---

<div align="center">

[← README](../README.md) · [Installation](INSTALL.md) · [Configuration](CONFIG.md) · [Architecture](ARCHITECTURE.md)

</div>
