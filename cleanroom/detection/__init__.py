"""Detection layer — the two-stage ensemble that scores each snapshot.

Mirrors Rubrik's approach: a behavioural (filesystem-metadata) stage and a
content (entropy) stage, fused into one explainable verdict. The heuristics are
transparent rules; the ML model (IsolationForest) catches oddities the rules
miss. A weighted :class:`~cleanroom.detection.scorer.Scorer` combines them.
"""

from cleanroom.detection.baseline import BaselineStats
from cleanroom.detection.engine import DetectionEngine
from cleanroom.detection.scorer import Scorer

__all__ = ["BaselineStats", "DetectionEngine", "Scorer"]
