"""VelocityDetector — the filesystem-metadata stage: how fast things changed.

Ransomware rewrites files far faster than a human ever would. We score the
change velocity as a z-score against the learned baseline, so 'fast' is defined
relative to *this* estate's normal rhythm, not a universal constant.
"""

from __future__ import annotations

from cleanroom.detection.baseline import BaselineStats
from cleanroom.detection.detectors.base import Detector, saturating
from cleanroom.domain import FeatureVector, SignalScore


class VelocityDetector(Detector):
    name = "velocity"

    @property
    def weight(self) -> float:
        return self._config.weight_velocity

    def evaluate(self, features: FeatureVector, baseline: BaselineStats) -> SignalScore:
        z = baseline.velocity_z(features.change_velocity)
        score = saturating(z, self._config.velocity_sigma)
        evidence = (
            f"change velocity {features.change_velocity:.4f}/s "
            f"(~{z:.1f}σ above baseline of {baseline.velocity_mean:.4f}/s)"
        )
        return self._signal(score, evidence)
