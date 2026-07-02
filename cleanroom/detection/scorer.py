"""Scorer — fuses signal scores into a single verdict.

Weighted normalised sum of every :class:`SignalScore` (heuristics + ML) → a
0..1 anomaly score, mapped to a :class:`Verdict` by the configured thresholds.
Kept deliberately simple and linear so a human can reproduce any verdict by hand
from the report — explainability over cleverness.
"""

from __future__ import annotations

from cleanroom.config import DetectionConfig
from cleanroom.domain import SignalScore, SnapshotAssessment, Verdict


class Scorer:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()

    def fuse(
        self,
        snapshot_id: str,
        signals: list[SignalScore],
        label: str | None = None,
    ) -> SnapshotAssessment:
        total_weight = sum(s.weight for s in signals) or 1.0
        anomaly_score = sum(s.weighted for s in signals) / total_weight
        anomaly_score = max(0.0, min(1.0, anomaly_score))

        verdict = self._verdict(anomaly_score)
        return SnapshotAssessment(
            snapshot_id=snapshot_id,
            verdict=verdict,
            anomaly_score=round(anomaly_score, 4),
            signals=tuple(signals),
            label=label,
        )

    def _verdict(self, score: float) -> Verdict:
        if score >= self._config.compromised_threshold:
            return Verdict.COMPROMISED
        if score >= self._config.suspicious_threshold:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN
