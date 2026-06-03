"""Registry and runner for secscan audit checks.

An audit check is a function that returns zero or more :class:`AuditFinding`
objects (a single finding, a list, or ``None``). Checks register themselves via
the ``@audit_check(category)`` decorator and live under
``secfesc.secscan.core.categories``. The :class:`AuditEngine` discovers and runs
them per category.

This is the secscan counterpart to ``secfesc.shared.registry`` (which serves
secfetch). Both share the same discovery/decorator idea; secscan checks return
the richer ``AuditFinding`` shape needed for a deep audit.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Callable, List, Optional, Union

from secfesc.secscan.core.engine import AuditFinding
from secfesc.shared.logger import log_debug, log_error

# A check returns one finding, several, or nothing.
CheckFunc = Callable[[], Union[AuditFinding, List[AuditFinding], None]]

_CHECKS: dict[str, list[CheckFunc]] = {}
_discovered = False


def audit_check(category: str) -> Callable[[CheckFunc], CheckFunc]:
    """Register a check function under *category*.

    The wrapped function is returned unchanged so it stays directly testable.
    """

    def wrapper(func: CheckFunc) -> CheckFunc:
        _CHECKS.setdefault(category, []).append(func)
        return func

    return wrapper


def _discover() -> None:
    """Import every module under secscan.core.categories so decorators fire."""
    global _discovered
    if _discovered:
        return
    import secfesc.secscan.core.categories as pkg

    for mod in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
        try:
            importlib.import_module(mod.name)
        except Exception as e:  # pragma: no cover - defensive
            log_error(f"Failed to load audit category module {mod.name}: {e}")
    _discovered = True


def registered_categories() -> list[str]:
    """Return the sorted list of categories that have at least one check."""
    _discover()
    return sorted(_CHECKS)


def has_checks(category: str) -> bool:
    _discover()
    return bool(_CHECKS.get(category))


def run_category(category: str) -> list[AuditFinding]:
    """Run all checks registered for *category* and return their findings.

    A check that raises is reported as a low-severity error finding rather than
    aborting the whole audit.
    """
    _discover()
    findings: list[AuditFinding] = []
    checks = _CHECKS.get(category, [])
    log_debug(f"Running {len(checks)} check(s) for category '{category}'")
    for func in checks:
        try:
            result: Optional[Union[AuditFinding, List[AuditFinding]]] = func()
        except Exception as e:
            findings.append(
                AuditFinding(
                    category=category,
                    check_id=f"{category.upper()}-ERR",
                    title=f"Check '{func.__name__}' raised an error",
                    severity="low",
                    status="error",
                    description=str(e),
                    solution="This is an internal audit error; please report it.",
                )
            )
            continue
        if result is None:
            continue
        if isinstance(result, AuditFinding):
            findings.append(result)
        else:
            findings.extend(result)
    return findings
