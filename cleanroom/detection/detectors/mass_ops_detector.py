"""MassOpsDetector — mass deletion / modification / rename in one snapshot.

Captures the volumetric tell that is dominant for wipers (mass delete) and for
rename+encrypt strains (mass rename/modify). Takes the strongest of the three
proportions so any one mass operation is enough to raise the signal.
"""

from __future__ import annotations

from cleanroom.detection.baseline import BaselineStats
from cleanroom.detection.detectors.base import Detector, saturating
from cleanroom.domain import FeatureVector, SignalScore


class MassOpsDetector(Detector):
    name = "mass_ops"

    @property
    def weight(self) -> float:
        return self._config.weight_mass_ops

    def evaluate(self, features: FeatureVector, baseline: BaselineStats) -> SignalScore:
        full = self._config.mass_delete_fraction
        delete_score = saturating(features.delete_ratio, full)
        # Bulk modify/rename saturate a bit slower than outright deletion.
        modify_score = saturating(features.modify_ratio, full * 4)
        rename_score = saturating(features.rename_ratio, full * 4)
        score = max(delete_score, modify_score, rename_score)

        evidence = (
            f"deleted {features.delete_ratio:.0%}, modified "
            f"{features.modify_ratio:.0%}, renamed {features.rename_ratio:.0%} "
            "of the corpus"
        )
        return self._signal(score, evidence)
