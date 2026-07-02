"""Recovery domain objects — the part that is distinctly *Rubrik*.

Detecting ransomware is table stakes. The differentiated outcome is telling an
operator: *this* is your last clean snapshot, and *this* is everything the
attack touched after it. Those are modelled here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class BlastRadius:
    """Cumulative impact of an attack from the infection point onward."""

    files_encrypted: int = 0
    files_deleted: int = 0
    files_added: int = 0        # ransom notes, dropped payloads
    files_renamed: int = 0
    bytes_affected: int = 0
    snapshots_impacted: int = 0
    affected_paths_sample: tuple[str, ...] = field(default_factory=tuple)

    @property
    def total_files_affected(self) -> int:
        return (
            self.files_encrypted
            + self.files_deleted
            + self.files_renamed
            + self.files_added
        )


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    """The engine's headline recommendation for an incident."""

    incident_detected: bool
    last_clean_snapshot_id: str | None
    first_compromised_snapshot_id: str | None
    blast_radius: BlastRadius
    recommendation: str
    confidence: float = 0.0

    def summary(self) -> str:
        if not self.incident_detected:
            return "No ransomware detected across the timeline. Backups are clean."
        return (
            f"Recover from snapshot {self.last_clean_snapshot_id}. "
            f"Attack first appears in {self.first_compromised_snapshot_id}, "
            f"impacting {self.blast_radius.total_files_affected} files "
            f"across {self.blast_radius.snapshots_impacted} snapshot(s)."
        )
