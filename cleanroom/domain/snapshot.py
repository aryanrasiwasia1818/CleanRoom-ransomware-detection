"""A Snapshot: an immutable point-in-time manifest of a protected file set.

This is the in-memory analogue of an immutable backup snapshot. Once created it
is never mutated (frozen dataclass) — the same guarantee that makes a real
immutable backup trustworthy makes our analysis reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping

from cleanroom.domain.file_record import FileRecord


@dataclass(frozen=True, slots=True)
class Snapshot:
    """An ordered, immutable set of :class:`FileRecord` at a moment in time.

    Attributes
    ----------
    snapshot_id:
        Monotonic identifier (``0001``, ``0002`` …) giving timeline order.
    taken_at:
        UTC timestamp the snapshot was captured.
    source:
        Human label for what was protected (a path, a volume name, …).
    files:
        Mapping of path -> FileRecord. A mapping (not a list) because path is
        the natural key and it makes diffing an O(n) set operation.
    label:
        Optional ground-truth annotation used only for benchmarking
        (``"clean"`` / ``"infected"``). Never consulted by the detector.
    """

    snapshot_id: str
    taken_at: datetime
    source: str
    files: Mapping[str, FileRecord] = field(default_factory=dict)
    label: str | None = None

    # ------------------------------------------------------------------ #
    @classmethod
    def create(
        cls,
        snapshot_id: str,
        source: str,
        records: Iterable[FileRecord],
        taken_at: datetime | None = None,
        label: str | None = None,
    ) -> "Snapshot":
        files = {r.path: r for r in records}
        return cls(
            snapshot_id=snapshot_id,
            taken_at=taken_at or datetime.now(timezone.utc),
            source=source,
            files=files,
            label=label,
        )

    # --- read-only aggregates -------------------------------------------- #
    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(r.size for r in self.files.values())

    def mean_entropy(self) -> float:
        if not self.files:
            return 0.0
        return sum(r.entropy for r in self.files.values()) / len(self.files)

    # --- (de)serialisation ------------------------------------------------ #
    def to_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "taken_at": self.taken_at.astimezone(timezone.utc).isoformat(),
            "source": self.source,
            "label": self.label,
            "files": [r.to_dict() for r in self.files.values()],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        records = (FileRecord.from_dict(f) for f in data.get("files", []))
        return cls.create(
            snapshot_id=data["snapshot_id"],
            source=data.get("source", ""),
            records=records,
            taken_at=datetime.fromisoformat(data["taken_at"]),
            label=data.get("label"),
        )
