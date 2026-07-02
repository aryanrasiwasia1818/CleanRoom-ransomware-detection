"""Services — stateless domain operations (capture, entropy, diff, features).

Each service does exactly one thing (Single-Responsibility) and depends only on
the domain layer and its injected config, never on interfaces or storage.
"""

from cleanroom.services.entropy import EntropyCalculator
from cleanroom.services.capturer import SnapshotCapturer
from cleanroom.services.differ import SnapshotDiffer
from cleanroom.services.feature_extractor import FeatureExtractor

__all__ = [
    "EntropyCalculator",
    "SnapshotCapturer",
    "SnapshotDiffer",
    "FeatureExtractor",
]
