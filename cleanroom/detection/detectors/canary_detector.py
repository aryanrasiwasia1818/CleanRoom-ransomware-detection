"""CanaryDetector — decoy files that should never legitimately change.

Canary (honeypot) files are planted in the corpus and touched by nothing during
normal operation. Any modification or deletion of one is an extremely strong,
low-false-positive indicator that something is walking the tree and encrypting
indiscriminately.
"""

from __future__ import annotations

from cleanroom.detection.baseline import BaselineStats
from cleanroom.detection.detectors.base import Detector
from cleanroom.domain import FeatureVector, SignalScore


class CanaryDetector(Detector):
    name = "canary"

    @property
    def weight(self) -> float:
        return self._config.weight_canary

    def evaluate(self, features: FeatureVector, baseline: BaselineStats) -> SignalScore:
        touched = features.canary_touched
        # One canary hit is already decisive; more only reinforces it.
        score = 1.0 if touched >= 1 else 0.0
        if touched:
            evidence = f"{touched} canary/decoy file(s) modified or deleted"
        else:
            evidence = "all canary files intact"
        return self._signal(score, evidence)
