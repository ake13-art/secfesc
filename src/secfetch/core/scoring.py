from __future__ import annotations

from secfetch.core.logger import log_warning
from secfetch.core.types import CategoryAccumulator, CheckResult

WEIGHTS: dict[str, int] = {"high": 30, "medium": 20, "low": 10, "info": 0}
_DEFAULT_WEIGHT = WEIGHTS["medium"]


def _get_weight(risk: str) -> int:
    weight = WEIGHTS.get(risk)
    if weight is None:
        log_warning(f"Unknown risk level '{risk}', defaulting to weight {_DEFAULT_WEIGHT}")
        return _DEFAULT_WEIGHT
    return weight


def calculate_score(results: list[CheckResult]) -> tuple[int, dict[str, int]]:
    """Calculate overall and per-category security scores.

    Scoring: ok = full points, warn = half points, bad/info = no points.
    """
    total = 0
    earned = 0
    categories: dict[str, CategoryAccumulator] = {}

    for result in results:
        weight = _get_weight(result["risk"])
        total += weight
        if result["status"] == "ok":
            points = weight
        elif result["status"] == "warn":
            points = weight // 2
        else:
            points = 0
        earned += points

        cat = categories.setdefault(result["category"], {"earned": 0, "total": 0})
        cat["total"] += weight
        cat["earned"] += points

    final = int((earned / total) * 100) if total else 0
    cat_scores = {
        k: int((v["earned"] / v["total"]) * 100) if v["total"] else 0 for k, v in categories.items()
    }
    return final, cat_scores
