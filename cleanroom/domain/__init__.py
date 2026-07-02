"""Domain layer — pure, dependency-free data model.

Nothing in this package imports numpy, sklearn, fastapi or touches the disk.
It is the *ubiquitous language* of the engine: snapshots, deltas, anomalies,
recovery plans. Keeping it pure (SRP + Dependency-Inversion) means the rules of
the domain never change just because the storage or ML library does.
"""

from cleanroom.domain.file_record import FileRecord
from cleanroom.domain.snapshot import Snapshot
from cleanroom.domain.delta import ChangeType, FileChange, SnapshotDelta
from cleanroom.domain.features import FeatureVector
from cleanroom.domain.anomaly import (
    Verdict,
    SignalScore,
    SnapshotAssessment,
    TimelineAssessment,
)
from cleanroom.domain.recovery import BlastRadius, RecoveryPlan

__all__ = [
    "FileRecord",
    "Snapshot",
    "ChangeType",
    "FileChange",
    "SnapshotDelta",
    "FeatureVector",
    "Verdict",
    "SignalScore",
    "SnapshotAssessment",
    "TimelineAssessment",
    "BlastRadius",
    "RecoveryPlan",
]
