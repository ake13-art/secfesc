<div align="center">

```
   ________  _____/ __/__  __________
  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/
 (__  )  __/ /__/ __/  __(__  ) /__
/____/\___/\___/_/  \___/____/\___/
```

[← README](../README.md) · [Installation](INSTALL.md) · [Usage](USAGE.md) · [Configuration](CONFIG.md)

# Architecture

*How secfesc is structured and how to add new checks.*

</div>

---

## Directory structure

```
src/secfesc/
├── shared/                  # Foundation — used by both tools
│   ├── registry.py          # @security_check decorator, runner, discovery
│   ├── colors.py            # ANSI colour constants
│   ├── config.py            # Config loading (~/.config/secfesc/checks.conf)
│   ├── error_handling.py    # safe_read_file / safe_subprocess_run / decorators
│   ├── logger.py            # Logging setup
│   ├── scoring.py           # Score calculation
│   └── types.py             # TypedDict definitions
│
├── checks/                  # secfetch checks (register via shared.registry)
│   ├── kernel/
│   ├── network/
│   ├── filesystem/
│   └── system/
│
├── secfetch/                # Quick security overview
│   ├── cli.py               # Argument parsing, command dispatch
│   ├── data/                # port_db, fix definitions
│   └── ui/
│       ├── output.py        # Full, live and short renderers (incl. logo config)
│       ├── help.py          # Per-check help text
│       └── improve.py       # Fix suggestions and auto-apply
│
└── secscan/                 # Deep audit (Lynis-style)
    ├── cli.py               # Argument parsing, exit codes, report dispatch
    ├── core/
    │   ├── engine.py        # AuditEngine, AuditFinding/Report, terminal rendering
    │   ├── registry.py      # @audit_check decorator, auto-discovery, runner
    │   └── categories/      # One module per audit category
    │       ├── ssh.py
    │       ├── users.py
    │       ├── groups.py
    │       ├── authentication.py
    │       ├── firewall.py
    │       ├── cron.py
    │       └── permissions.py
    └── report/              # Export formats
        ├── json.py
        ├── html.py
        └── csv.py
```

The two tools share one foundation in `shared/`. secfetch checks register through `shared/registry.py`; secscan checks register through `secscan/core/registry.py` and return the richer `AuditFinding` type needed for a deep audit.

---

## Adding a secfetch check

1. Create a module in `checks/<category>/`
2. Register with the decorator:

```python
from secfesc.shared.registry import security_check

@security_check(name="My Check", category="network", risk="medium")
def check() -> dict[str, str]:
    return {"status": "ok", "value": "everything fine"}
```

3. Add a description in `secfetch/ui/help.py`

Status values: `ok` · `warn` · `bad` · `info`

---

## Adding a secscan check

1. Create or open `secscan/core/categories/<category>.py`
2. Write a function decorated with `@audit_check("<category>")`:

```python
from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check

@audit_check("ssh")
def check_example() -> AuditFinding | None:
    return AuditFinding(
        category="ssh",
        check_id="SSH-1234",
        title="Something is misconfigured",
        severity="high",        # high → error  |  medium → warning  |  low → note
        status="found",
        description="What is wrong and why it matters.",
        solution="The exact command or config change to fix it.",
        affected="the offending value (optional)",
    )
```

Discovery and the runner pick it up automatically — no manual registration needed.

> [!NOTE]
> A check function can also return a `list[AuditFinding]` (multiple findings) or `None` (nothing to report). Unhandled exceptions are caught and degraded to an error finding so one broken check can never abort the whole audit.

---

## Adding a short-mode logo

Logos are defined in `secfetch/ui/output.py` in the `LOGOS` dict. Each logo is a `list[str]` of equal or variable-length lines. Add your logo there:

```python
LOGOS: dict[str, list[str]] = {
    "secfesc": [...],   # default
    "arch": [...],
    "mylogo": [         # ← add yours here
        r" ___ ",
        r"|   |",
        r"|___|",
        r"",
        r"",
    ],
}
```

Then set it in `~/.config/secfesc/checks.conf`:

```ini
[display]
logo = mylogo
```

---

## Testing

```bash
# Install dev dependencies
uv sync --extra dev
# or: pip install -e ".[dev]"

# Run tests with coverage
uv run pytest --cov=src/secfesc

# Lint
ruff check src tests
```

Coverage target: **100%**. Add tests for every new branch you introduce.

---

<div align="center">

[← README](../README.md) · [Installation](INSTALL.md) · [Usage](USAGE.md) · [Configuration](CONFIG.md)

</div>
