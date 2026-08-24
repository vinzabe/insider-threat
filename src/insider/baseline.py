"""Rolling per-entity baselines. Pure-Python running statistics (Welford) so a
baseline updates in O(1) per event and never stores raw history unbounded.
"""
from __future__ import annotations

import dataclasses
import math


@dataclasses.dataclass(slots=True)
class RunningStat:
    """Welford's online mean/variance."""
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, x: float) -> float:
        s = self.std
        if s == 0.0:
            # A perfectly constant baseline gives us no scale to judge deviation.
            # A change IS notable, but we must not fabricate a large z-score from
            # no variance. Return a modest signal (1.0) so a lone zero-variance
            # metric is visible but never alone crosses the elevation threshold.
            return 0.0 if x == self.mean else math.copysign(1.0, x - self.mean)
        return (x - self.mean) / s


@dataclasses.dataclass(slots=True)
class Baseline:
    """Per-metric running stats for one entity (a user or a peer group)."""
    warmup: int = 14
    metrics: dict[str, RunningStat] = dataclasses.field(default_factory=dict)

    def observe(self, features: dict[str, float]) -> None:
        for k, v in features.items():
            self.metrics.setdefault(k, RunningStat()).update(v)

    @property
    def observations(self) -> int:
        return max((s.n for s in self.metrics.values()), default=0)

    @property
    def ready(self) -> bool:
        return self.observations >= self.warmup

    def zscores(self, features: dict[str, float]) -> dict[str, float]:
        return {k: self.metrics[k].zscore(v)
                for k, v in features.items() if k in self.metrics}
