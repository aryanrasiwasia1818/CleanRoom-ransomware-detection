"""Ransomware families as interchangeable Strategy objects.

Each family knows how to progress an attack across one or more snapshot
"stages". The :class:`RansomwareFamily` base class implements the *template
method* ``run_stage`` (common concerns: selecting targets, dropping ransom
notes) and defers the strain-specific mutation to :meth:`_attack_file`.

Adding a new strain = one subclass. The timeline engine never changes.
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from pathlib import Path

_RANSOM_NOTE = (
    "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\n"
    "All your important data has been locked with military-grade encryption.\n"
    "To recover your files you must pay within 72 hours.\n"
    "Do not attempt to restore from backups - they cannot help you.\n"
)

# File types a typical strain targets (user data, not system/media by default).
_TARGET_SUFFIXES = {".txt", ".csv", ".md", ".py", ".json", ".xlsx", ".docx"}


class RansomwareFamily(ABC):
    """Base Strategy for a ransomware strain."""

    #: Stable identifier used on the CLI (``--family lockbit``).
    name: str = "base"
    #: One-line human description shown in reports.
    description: str = ""
    #: Number of snapshots the attack unfolds over (1 = single-shot).
    stages: int = 1
    #: Extension appended to encrypted files ("" = encrypt in place, no rename).
    marker_extension: str = ""

    # ------------------------------------------------------------------ #
    # Public template method
    # ------------------------------------------------------------------ #
    def run_stage(self, root: str | Path, rng: random.Random, stage: int) -> None:
        """Advance the attack by one stage (0-indexed)."""
        root = Path(root)
        targets = self._select_targets(root, rng, stage)
        for path in targets:
            self._attack_file(path, rng, stage)
        self._maybe_drop_notes(root, stage)

    # ------------------------------------------------------------------ #
    # Hooks / helpers
    # ------------------------------------------------------------------ #
    def _candidate_files(self, root: Path) -> list[Path]:
        return [
            p
            for p in root.rglob("*")
            if p.is_file()
            and p.suffix in _TARGET_SUFFIXES
            and not p.name.startswith("RESTORE_FILES")
            and self.marker_extension not in p.suffixes
        ]

    @abstractmethod
    def _select_targets(
        self, root: Path, rng: random.Random, stage: int
    ) -> list[Path]:
        """Choose which files this stage will hit."""

    @abstractmethod
    def _attack_file(self, path: Path, rng: random.Random, stage: int) -> None:
        """Mutate one file (encrypt / rename / delete)."""

    def _maybe_drop_notes(self, root: Path, stage: int) -> None:
        """Drop ransom notes on the final stage (default behaviour)."""
        if stage == self.stages - 1:
            for subdir in {p.parent for p in root.rglob("*") if p.is_file()}:
                (subdir / "RESTORE_FILES.txt").write_text(_RANSOM_NOTE)

    # --- shared encryption primitives --------------------------------- #
    @staticmethod
    def _overwrite_random(path: Path, rng: random.Random, fraction: float = 1.0) -> None:
        """Overwrite ``fraction`` of the file with random bytes (raises entropy)."""
        size = path.stat().st_size
        original = path.read_bytes() if fraction < 1.0 else b""
        n_random = max(1, int(size * fraction)) if size else 1024
        blob = bytes(rng.getrandbits(8) for _ in range(n_random))
        if fraction >= 1.0:
            path.write_bytes(blob)
        else:
            # Intermittent encryption: encrypt a prefix, keep the tail.
            path.write_bytes(blob + original[n_random:])

    def _encrypt_and_rename(
        self, path: Path, rng: random.Random, fraction: float = 1.0
    ) -> None:
        self._overwrite_random(path, rng, fraction)
        if self.marker_extension:
            path.rename(path.with_name(path.name + self.marker_extension))


# --------------------------------------------------------------------------- #
# Concrete families
# --------------------------------------------------------------------------- #


class LockBitStyleFamily(RansomwareFamily):
    """Fast, loud 'rename + encrypt' strain (LockBit / Conti archetype).

    Encrypts the vast majority of user files in a single snapshot, renaming each
    with a ``.lockbit`` marker and dropping ransom notes everywhere. The textbook
    case: huge entropy jump + mass rename + suspicious extension all at once.
    """

    name = "lockbit"
    description = "Fast full-encryption with rename + ransom notes (LockBit-style)."
    stages = 1
    marker_extension = ".lockbit"

    def _select_targets(self, root, rng, stage):
        candidates = self._candidate_files(root)
        rng.shuffle(candidates)
        keep = int(len(candidates) * rng.uniform(0.80, 0.95))
        return candidates[:keep]

    def _attack_file(self, path, rng, stage):
        self._encrypt_and_rename(path, rng, fraction=1.0)


class IntermittentEncryptorFamily(RansomwareFamily):
    """Stealthy 'slow-burn' strain using intermittent encryption.

    Spreads across several snapshots, encrypting only part of each file (so the
    per-snapshot entropy jump is smaller and volume is lower). Designed to slip
    past crude thresholds — the reason CleanRoom fuses multiple weak signals plus
    an ML baseline rather than trusting a single rule.
    """

    name = "intermittent"
    description = "Stealthy multi-stage partial encryption (intermittent/slow-burn)."
    stages = 3
    marker_extension = ".crypt"

    def _select_targets(self, root, rng, stage):
        candidates = self._candidate_files(root)
        rng.shuffle(candidates)
        # ~30% of remaining un-encrypted files each stage.
        take = max(1, int(len(candidates) * rng.uniform(0.25, 0.35)))
        return candidates[:take]

    def _attack_file(self, path, rng, stage):
        self._encrypt_and_rename(path, rng, fraction=rng.uniform(0.4, 0.6))


class WiperFamily(RansomwareFamily):
    """Destructive wiper: mass deletion plus garbage overwrites.

    Not really about ransom — it destroys data. The dominant signal is mass
    deletion + high change velocity rather than entropy, which is exactly why the
    mass-ops detector exists alongside the entropy detector.
    """

    name = "wiper"
    description = "Destructive mass deletion with garbage overwrites (wiper)."
    stages = 1
    marker_extension = ""

    def _select_targets(self, root, rng, stage):
        candidates = self._candidate_files(root)
        rng.shuffle(candidates)
        keep = int(len(candidates) * rng.uniform(0.70, 0.90))
        return candidates[:keep]

    def _attack_file(self, path, rng, stage):
        # 60% deleted outright, the rest overwritten with garbage.
        if rng.random() < 0.6:
            path.unlink(missing_ok=True)
        else:
            self._overwrite_random(path, rng, fraction=1.0)


# --------------------------------------------------------------------------- #
# Registry (Factory)
# --------------------------------------------------------------------------- #

FAMILIES: dict[str, type[RansomwareFamily]] = {
    LockBitStyleFamily.name: LockBitStyleFamily,
    IntermittentEncryptorFamily.name: IntermittentEncryptorFamily,
    WiperFamily.name: WiperFamily,
}


def get_family(name: str) -> RansomwareFamily:
    """Factory: instantiate a family by its CLI name."""
    try:
        return FAMILIES[name]()
    except KeyError:
        raise ValueError(
            f"Unknown family {name!r}. Choose from: {', '.join(FAMILIES)}"
        ) from None
