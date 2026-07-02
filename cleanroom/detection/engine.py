"""DetectionEngine — composes the heuristic Strategies + ML into a verdict stream.

Responsibilities (and only these): learn the baseline, run every detector plus
the ML model over each snapshot's features, and fuse the results. It depends on
*abstractions* (a list of :class:`Detector`, an :class:`AnomalyModel`, a
:class:`Scorer`), all injectable — so a test can pass a single fake detector, and
a future signal is added without touching this class.
"""

from __future__ import annotations

from cleanroom.config import Config
from cleanroom.detection.baseline import BaselineStats
from cleanroom.detection.detectors import (
    CanaryDetector,
    Detector,
    EntropyDetector,
    ExtensionDetector,
    MassOpsDetector,
    VelocityDetector,
)
from cleanroom.detection.ml_model import AnomalyModel
from cleanroom.detection.scorer import Scorer
from cleanroom.domain import (
    FeatureVector,
    SignalScore,
    TimelineAssessment,
)


def default_detectors(config) -> list[Detector]:
    """Factory for the standard heuristic detector suite (in report order)."""
    return [
        EntropyDetector(config),
        MassOpsDetector(config),
        VelocityDetector(config),
        ExtensionDetector(config),
        CanaryDetector(config),
    ]


class DetectionEngine:
    def __init__(
        self,
        config: Config | None = None,
        detectors: list[Detector] | None = None,
        model: AnomalyModel | None = None,
        scorer: Scorer | None = None,
    ) -> None:
        self._config = config or Config()
        self._detectors = detectors or default_detectors(self._config.detection)
        self._model = model or AnomalyModel(self._config.ml)
        self._scorer = scorer or Scorer(self._config.detection)

    # ------------------------------------------------------------------ #
    def assess(
        self,
        features: list[FeatureVector],
        labels: dict[str, str] | None = None,
    ) -> TimelineAssessment:
        """Score an ordered list of per-snapshot feature vectors."""
        labels = labels or {}
        n_baseline = min(self._config.detection.baseline_snapshots, len(features))
        baseline_features = features[:n_baseline]

        baseline_stats = BaselineStats.from_features(baseline_features)
        self._model.fit(baseline_features)

        assessments = []
        for fv in features:
            signals = [d.evaluate(fv, baseline_stats) for d in self._detectors]
            signals.append(self._ml_signal(fv))
            assessments.append(
                self._scorer.fuse(fv.snapshot_id, signals, labels.get(fv.snapshot_id))
            )
        return TimelineAssessment(tuple(assessments))

    # ------------------------------------------------------------------ #
    def _ml_signal(self, fv: FeatureVector) -> SignalScore:
        score = self._model.score(fv)
        if not self._model.is_fitted:
            evidence = "ML baseline inactive (insufficient history)"
        else:
            evidence = f"IsolationForest anomaly score {score:.2f} vs baseline"
        return SignalScore(
            name="ml_anomaly",
            score=score,
            weight=self._config.detection.weight_ml,
            evidence=evidence,
        )
