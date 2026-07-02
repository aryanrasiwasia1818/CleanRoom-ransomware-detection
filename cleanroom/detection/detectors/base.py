"""The Detector Strategy interface plus a small shared helper."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cleanroom.config import DetectionConfig
from cleanroom.detection.baseline import BaselineStats
from cleanroom.domain import FeatureVector, SignalScore


def saturating(value: float, full_scale: float) -> float:
    """Map ``value`` to 0..1, reaching 1.0 at ``full_scale`` (linear ramp)."""
    if full_scale <= 0:
        return 1.0 if value > 0 else 0.0
    return max(0.0, min(1.0, value / full_scale))


class Detector(ABC):
    """A single, explainable ransomware signal.

    Contract: given the current snapshot's features and the learned baseline,
    return a :class:`SignalScore` in [0, 1] with human-readable evidence. A
    detector must be a pure function of its inputs — no hidden state — so the
    ensemble is deterministic and testable.
    """

    #: Stable signal name shown in reports.
    name: str = "base"

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()

    @property
    @abstractmethod
    def weight(self) -> float:
        """Relative importance of this signal in the fused score."""

    @abstractmethod
    def evaluate(
        self, features: FeatureVector, baseline: BaselineStats
    ) -> SignalScore:
        """Score the snapshot on this detector's dimension."""

    # Convenience for subclasses.
    def _signal(self, score: float, evidence: str) -> SignalScore:
        return SignalScore(
            name=self.name,
            score=max(0.0, min(1.0, score)),
            weight=self.weight,
            evidence=evidence,
        )
