"""BaselineStats — the learned 'normal' the detectors compare against.

Rubrik Radar builds a historical baseline that it refines over time; this is the
minimal version of that idea. We summarise the benign snapshots' feature vectors
into per-feature mean/std so detectors can compute robust z-scores instead of
relying only on absolute thresholds.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from cleanroom.domain import FeatureVector


@dataclass(frozen=True, slots=True)
class BaselineStats:
    """Mean/std of key features across the trusted baseline snapshots."""

    velocity_mean: float = 0.0
    velocity_std: float = 0.0
    change_ratio_mean: float = 0.0
    change_ratio_std: float = 0.0
    sample_size: int = 0

    @classmethod
    def from_features(cls, features: list[FeatureVector]) -> "BaselineStats":
        # Ignore genesis / empty vectors (all-zero change) when learning normal.
        active = [f for f in features if f.change_ratio > 0] or features
        if not active:
            return cls()
        velocities = [f.change_velocity for f in active]
        change_ratios = [f.change_ratio for f in active]
        return cls(
            velocity_mean=statistics.fmean(velocities),
            velocity_std=statistics.pstdev(velocities) if len(velocities) > 1 else 0.0,
            change_ratio_mean=statistics.fmean(change_ratios),
            change_ratio_std=(
                statistics.pstdev(change_ratios) if len(change_ratios) > 1 else 0.0
            ),
            sample_size=len(active),
        )

    def velocity_z(self, value: float) -> float:
        """Z-score of a velocity vs baseline (0 if std is unknown/zero)."""
        if self.velocity_std <= 1e-9:
            # No variance observed: fall back to a ratio vs the mean.
            if self.velocity_mean <= 1e-9:
                return 0.0
            return max(0.0, (value - self.velocity_mean) / self.velocity_mean)
        return (value - self.velocity_mean) / self.velocity_std
