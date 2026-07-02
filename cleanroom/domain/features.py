"""The numeric feature vector extracted from one snapshot delta.

This is the shared contract between the :mod:`cleanroom.detection` heuristics and
the ML model. Heuristics read named fields (explainable); the ML model reads the
same values as an ordered array (:meth:`as_array`). Single source of truth →
no drift between the two halves of the ensemble.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import ClassVar


@dataclass(frozen=True, slots=True)
class FeatureVector:
    """Per-snapshot behavioural + content features (all delta-relative)."""

    snapshot_id: str

    # --- volume / velocity (filesystem-metadata stage) ------------------- #
    change_ratio: float          # files changed / previous file count
    add_ratio: float             # files added / previous file count
    delete_ratio: float          # files deleted / previous file count
    modify_ratio: float          # files modified / previous file count
    rename_ratio: float          # files renamed / previous file count
    change_velocity: float       # changes per second

    # --- content / entropy (file-content stage) -------------------------- #
    mean_entropy_delta: float    # average entropy jump over changed files
    max_entropy_delta: float
    high_entropy_fraction: float # fraction of changed files now >= threshold

    # --- extension / naming --------------------------------------------- #
    suspicious_ext_fraction: float
    distinct_new_extensions: int

    # --- decoys ---------------------------------------------------------- #
    canary_touched: int          # count of canary files changed/deleted

    # Ordered feature names used to build the ML matrix.
    ML_FEATURES: ClassVar[tuple[str, ...]] = (
        "change_ratio",
        "add_ratio",
        "delete_ratio",
        "modify_ratio",
        "rename_ratio",
        "change_velocity",
        "mean_entropy_delta",
        "max_entropy_delta",
        "high_entropy_fraction",
        "suspicious_ext_fraction",
        "distinct_new_extensions",
        "canary_touched",
    )

    def as_array(self) -> list[float]:
        """Ordered numeric vector for the ML model (matches ``ML_FEATURES``)."""
        return [float(getattr(self, name)) for name in self.ML_FEATURES]

    def to_dict(self) -> dict:
        return asdict(self)
