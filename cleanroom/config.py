"""Central, typed configuration for the whole engine.

Every tunable lives here so behaviour is auditable and reproducible — an
explicit nod to Rubrik's *Transparency* value: nothing about a verdict should be
hidden in a magic number buried three call-frames deep.

Thresholds are expressed as *value objects* (frozen dataclasses). They can be
overridden from the environment (``CLEANROOM_*``) or constructed directly in
tests, keeping the detection logic free of global state.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace

# --------------------------------------------------------------------------- #
# Entropy
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EntropyConfig:
    """Parameters for block-level Shannon-entropy sampling of file content."""

    block_size: int = 4096
    """Bytes per sampled block (mirrors a typical filesystem block)."""

    max_blocks: int = 64
    """Cap on blocks sampled per file — keeps large-file scanning O(1)."""

    high_entropy_threshold: float = 7.9
    """Bits/byte at/above which content is treated as encrypted/compressed.

    Random (encrypted) data approaches the theoretical maximum of 8.0 bits/byte;
    natural files (text, source, office docs) sit well below.
    """


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DetectionConfig:
    """Weights + thresholds that turn per-signal scores into a verdict.

    Weights are relative; the scorer normalises them, so they need not sum to 1.
    """

    # Fusion weights for each heuristic + the ML model (need not sum to 1).
    # Tuned so no single noisy signal can convict, but any two strong,
    # high-confidence signals (e.g. suspicious extension + mass modify) will.
    weight_entropy: float = 0.28
    weight_mass_ops: float = 0.22
    weight_extension: float = 0.20
    weight_velocity: float = 0.12
    weight_canary: float = 0.10
    weight_ml: float = 0.08

    # Verdict cut-offs on the fused 0..1 score. Benign churn scores well under
    # 0.20 in practice, leaving a wide margin below "suspicious".
    suspicious_threshold: float = 0.30
    compromised_threshold: float = 0.50

    # Entropy magnitude that fully saturates the entropy signal (bits/byte).
    # ~2.5 lets *partial* (intermittent) encryption still register meaningfully.
    entropy_delta_full_scale: float = 2.5

    # Number of leading snapshots trusted as "clean" to train the baseline
    # (the historical baseline Rubrik Radar refines over time).
    baseline_snapshots: int = 3

    # Individual heuristic sensitivities.
    entropy_spike_fraction: float = 0.15
    """Fraction of changed files turning high-entropy to saturate the signal."""

    velocity_sigma: float = 3.0
    """Z-score of change-velocity vs baseline to saturate the signal."""

    mass_delete_fraction: float = 0.10
    """Fraction of the corpus deleted to saturate the mass-op signal."""

    suspicious_extensions: tuple[str, ...] = (
        ".locked", ".crypt", ".crypted", ".encrypted", ".enc", ".ryk",
        ".lockbit", ".conti", ".ryuk", ".wcry", ".wncry", ".cerber",
        ".zzz", ".vault", ".onion", ".pay", ".r5a", ".cry",
    )
    """Known ransomware extension markers (extended at runtime by churn stats)."""

    canary_filenames: tuple[str, ...] = (
        "DO_NOT_DELETE_canary.docx",
        "_canary_finance.xlsx",
        "zzz_canary_readme.txt",
    )
    """Decoy files planted in the corpus; any change to them is a strong tell."""


# --------------------------------------------------------------------------- #
# ML
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MLConfig:
    """IsolationForest hyper-parameters for the unsupervised anomaly model."""

    n_estimators: int = 200
    contamination: float = 0.1
    random_state: int = 42


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class StorageConfig:
    """Where immutable snapshot manifests live."""

    root: str = "data/snapshots"
    manifest_suffix: str = ".snapshot.json"


# --------------------------------------------------------------------------- #
# Root
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Config:
    """Aggregate root config — the single object threaded through the engine."""

    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _get_float(name: str, default: float) -> float:
        raw = os.environ.get(name)
        return float(raw) if raw is not None else default

    @classmethod
    def from_env(cls) -> "Config":
        """Build a config, letting a few high-value knobs be overridden by env."""
        base = cls()
        detection = replace(
            base.detection,
            suspicious_threshold=cls._get_float(
                "CLEANROOM_SUSPICIOUS_THRESHOLD", base.detection.suspicious_threshold
            ),
            compromised_threshold=cls._get_float(
                "CLEANROOM_COMPROMISED_THRESHOLD", base.detection.compromised_threshold
            ),
        )
        entropy = replace(
            base.entropy,
            high_entropy_threshold=cls._get_float(
                "CLEANROOM_HIGH_ENTROPY", base.entropy.high_entropy_threshold
            ),
        )
        storage = replace(
            base.storage,
            root=os.environ.get("CLEANROOM_STORAGE_ROOT", base.storage.root),
        )
        return replace(base, detection=detection, entropy=entropy, storage=storage)


DEFAULT_CONFIG = Config()
