# Architecture

Project structure for secfesc.

---

## Directory Structure

```
src/secfesc/
├── shared/                  # Shared foundation, used by BOTH tools
│   ├── registry.py          # @security_check decorator + registry + runner
│   ├── colors.py            # ANSI colours
│   ├── config.py            # Config loading
│   ├── error_handling.py    # safe_read_file / safe_subprocess_run / decorators
│   ├── logger.py            # Logging
│   ├── scoring.py           # Score calculation
│   ├── types.py             # TypedDict definitions
│   └── help.py              # Help text
├── checks/                  # secfetch checks (register via shared.registry)
│   ├── kernel/
│   ├── network/
│   ├── filesystem/
│   └── system/
├── secfetch/                # Quick security overview
│   ├── cli.py
│   ├── data/                # port_db, fix data
│   └── ui/                  # output / help / improve (compact rendering)
└── secscan/                 # Deep audit (Lynis-style)
    ├── cli.py
    ├── core/
    │   ├── engine.py        # AuditEngine, AuditFinding/Report, rendering
    │   ├── registry.py      # @audit_check decorator + discovery + runner
    │   └── categories/      # one module per audit category (ssh, users, groups, …)
    └── report/              # Export formats (json.py, html.py, csv.py)
```

The two tools share one foundation in `shared/`. secfetch checks register through
`shared/registry.py`; secscan checks register through `secscan/core/registry.py`
and return the richer `AuditFinding` shape needed for a deep audit.

---

## Adding a check (secfetch)

1. Create a check file in `checks/<category>/`
2. Register it with the decorator:

```python
from secfesc.shared.registry import security_check

@security_check(name="My Check", category="network", risk="medium")
def check() -> dict[str, str]:
    return {"status": "ok", "value": "Good"}
```

3. Add a description in `shared/help.py`

---

## Adding a check (secscan)

1. Add (or open) a module in `secscan/core/categories/<category>.py`
2. Write a function decorated with `@audit_check("<category>")` returning an
   `AuditFinding`, a list of them, or `None`:

```python
from secfesc.secscan.core.engine import AuditFinding
from secfesc.secscan.core.registry import audit_check

@audit_check("ssh")
def check_example() -> AuditFinding | None:
    return AuditFinding(
        category="ssh",
        check_id="SSH-1234",
        title="Something is misconfigured",
        severity="high",        # high -> error, medium -> warning, low -> note
        status="found",
        description="What is wrong.",
        solution="How to fix it.",
        affected="the offending value",
    )
```

Discovery and the runner pick it up automatically — no manual registration.

---

## Testing

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
```
