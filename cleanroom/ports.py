"""Ports (abstract interfaces) — the seams that keep the core decoupled.

Following the Dependency-Inversion Principle, high-level policy (the pipeline,
the recovery analyzer) depends on these abstractions, never on a concrete
database or filesystem. Implementations live in :mod:`cleanroom.infrastructure`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from cleanroom.domain import Snapshot


class SnapshotRepository(ABC):
    """An append-only, ordered store of immutable snapshots.

    'Append-only' is the software mirror of an immutable backup: existing
    snapshots can be read but never rewritten, so the forensic record cannot be
    tampered with after the fact.
    """

    @abstractmethod
    def append(self, snapshot: Snapshot) -> None:
        """Persist a new snapshot. Must reject overwriting an existing id."""

    @abstractmethod
    def get(self, snapshot_id: str) -> Snapshot:
        """Load a single snapshot by id (raises ``KeyError`` if missing)."""

    @abstractmethod
    def list_ids(self) -> list[str]:
        """Return snapshot ids in timeline order."""

    @abstractmethod
    def __iter__(self) -> Iterator[Snapshot]:
        """Iterate snapshots in timeline order."""

    def __len__(self) -> int:
        return len(self.list_ids())
