from __future__ import annotations

import random
from typing import Callable, Sequence


def bootstrap_ci(
    items: Sequence,
    metric_fn: Callable[[list], float],
    *,
    seed: int = 42,
    n_resamples: int = 500,
    alpha: float = 0.05,
) -> dict[str, float]:
    """Return a deterministic percentile bootstrap confidence interval."""

    if not items:
        return {"estimate": 0.0, "ci_low": 0.0, "ci_high": 0.0, "n": 0}
    rng = random.Random(seed)
    items = list(items)
    estimates = []
    for _ in range(n_resamples):
        sample = [items[rng.randrange(len(items))] for _ in items]
        estimates.append(float(metric_fn(sample)))
    estimates.sort()
    low_idx = max(0, int((alpha / 2) * len(estimates)))
    high_idx = min(len(estimates) - 1, int((1 - alpha / 2) * len(estimates)) - 1)
    return {
        "estimate": float(metric_fn(list(items))),
        "ci_low": estimates[low_idx],
        "ci_high": estimates[high_idx],
        "n": len(items),
    }


def bootstrap_paired_difference_ci(
    pairs: Sequence[tuple],
    metric_fn: Callable[[list], float],
    *,
    seed: int = 42,
    n_resamples: int = 500,
    alpha: float = 0.05,
) -> dict[str, float]:
    return bootstrap_ci(pairs, metric_fn, seed=seed, n_resamples=n_resamples, alpha=alpha)
