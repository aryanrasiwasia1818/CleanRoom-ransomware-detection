"""ExtensionDetector — suspicious new file extensions (e.g. ``.locked``).

Many strains append a signature extension to every file they touch. Even a small
proportion of known-bad extensions is a high-confidence tell, so this signal
ramps up quickly.
"""

from __future__ import annotations

from cleanroom.detection.baseline import BaselineStats
from cleanroom.detection.detectors.base import Detector, saturating
from cleanroom.domain import FeatureVector, SignalScore


class ExtensionDetector(Detector):
    name = "extension"

    @property
    def weight(self) -> float:
        return self._config.weight_extension

    def evaluate(self, features: FeatureVector, baseline: BaselineStats) -> SignalScore:
        # 5% of changes carrying a known ransomware extension already saturates.
        score = saturating(features.suspicious_ext_fraction, 0.05)
        evidence = (
            f"{features.suspicious_ext_fraction:.0%} of changes use known "
            f"ransomware extensions ({features.distinct_new_extensions} new "
            "extension types this snapshot)"
        )
        return self._signal(score, evidence)
