"""EntropyDetector — the file-content stage; the encryption signature.

Fires when a meaningful fraction of changed files jump into the high-entropy
band (near-random content). Combines the *breadth* of the jump (fraction of
changed files) with its *magnitude* (mean entropy delta) so a large jump across
many files scores highest.
"""

from __future__ import annotations

from cleanroom.detection.baseline import BaselineStats
from cleanroom.detection.detectors.base import Detector, saturating
from cleanroom.domain import FeatureVector, SignalScore


class EntropyDetector(Detector):
    name = "entropy"

    @property
    def weight(self) -> float:
        return self._config.weight_entropy

    def evaluate(self, features: FeatureVector, baseline: BaselineStats) -> SignalScore:
        breadth = saturating(
            features.high_entropy_fraction, self._config.entropy_spike_fraction
        )
        # A jump toward the 8.0 ceiling is the encryption signature; the
        # full-scale is configurable so partial (intermittent) encryption counts.
        magnitude = saturating(
            features.mean_entropy_delta, self._config.entropy_delta_full_scale
        )
        # Breadth dominates; magnitude confirms.
        score = 0.65 * breadth + 0.35 * magnitude

        evidence = (
            f"{features.high_entropy_fraction:.0%} of changed files now "
            f"high-entropy, mean +{features.mean_entropy_delta:.2f} bits/byte "
            f"(peak +{features.max_entropy_delta:.2f})"
        )
        return self._signal(score, evidence)
