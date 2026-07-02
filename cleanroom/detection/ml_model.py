"""Unsupervised anomaly model — the ML half of the ensemble.

An IsolationForest is trained *only* on the trusted baseline snapshots, so it
learns what this estate's normal churn looks like and flags snapshots that sit
far from it. Unsupervised is the right fit: real deployments have plenty of clean
history but (hopefully) no labelled attacks to train a classifier on.

The model is optional by design — if scikit-learn is unavailable or there are too
few baseline samples, :meth:`score` degrades gracefully to 0.0 and the
transparent heuristics carry the verdict on their own.
"""

from __future__ import annotations

from cleanroom.config import MLConfig
from cleanroom.domain import FeatureVector

try:  # ML is a soft dependency.
    import numpy as np
    from sklearn.ensemble import IsolationForest

    _SKLEARN = True
except Exception:  # pragma: no cover - exercised only when sklearn missing
    _SKLEARN = False


class AnomalyModel:
    """Thin, well-behaved wrapper around IsolationForest."""

    #: Minimum baseline samples before training is worthwhile.
    MIN_SAMPLES = 3

    def __init__(self, config: MLConfig | None = None) -> None:
        self._config = config or MLConfig()
        self._model = None
        self._fitted = False

    @property
    def is_available(self) -> bool:
        return _SKLEARN

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    # ------------------------------------------------------------------ #
    def fit(self, baseline: list[FeatureVector]) -> "AnomalyModel":
        """Train on baseline vectors. No-op (safe) if it can't or shouldn't."""
        if not _SKLEARN or len(baseline) < self.MIN_SAMPLES:
            self._fitted = False
            return self

        matrix = np.array([f.as_array() for f in baseline], dtype=float)
        self._model = IsolationForest(
            n_estimators=self._config.n_estimators,
            contamination=self._config.contamination,
            random_state=self._config.random_state,
        )
        self._model.fit(matrix)
        self._fitted = True
        return self

    # ------------------------------------------------------------------ #
    def score(self, features: FeatureVector) -> float:
        """Return an anomaly score in [0, 1] (0 when the model is inactive)."""
        if not self._fitted or self._model is None:
            return 0.0

        vector = np.array([features.as_array()], dtype=float)
        # decision_function: higher = more normal. Negate and squash to 0..1.
        raw = float(self._model.decision_function(vector)[0])
        # A raw score of 0 is the trained decision boundary; below it is anomalous.
        return max(0.0, min(1.0, -raw * 2.0)) if raw < 0 else 0.0
