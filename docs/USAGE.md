# Usage Guide

## secfetch

Quick security overview.

```bash
secfetch              # Full overview
secfetch --short      # Compact box
secfetch help         # List checks
secfetch help <name> # Check details
```

## secscan

Comprehensive security audit.

```bash
secscan                    # Basic audit (no root)
secscan --full             # Complete audit (requires root)
secscan --quick            # Essential checks only
secscan --category ssh     # Specific category
secscan --report json      # Export results to stdout (clean, machine-readable)
secscan --report html --output audit.html   # Export to a file
secscan --quiet            # Suppress the human summary
```

When `--report` is written to stdout (no `--output`), the human summary is
suppressed so the JSON/CSV/HTML stream stays clean and parseable.

---

## Examples

### Daily Security Check

```bash
secfetch
```

### Weekly Full Audit

```bash
sudo secscan --full
```

### Export Report

```bash
secscan --report html --output audit.html
```

---

## Exit Codes (secscan)

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings |
| 1 | Warnings found (medium severity) |
| 2 | Errors found (high severity) |
| 3 | Fatal error |
| 130 | Interrupted (Ctrl+C) |

This makes secscan usable in CI: a non-zero exit means something needs attention.
