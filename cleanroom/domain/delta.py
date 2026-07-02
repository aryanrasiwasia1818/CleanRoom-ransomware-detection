"""The delta between two consecutive snapshots — the engine's primary signal.

Rubrik-style detection never re-scans production; it reasons over *what changed*
between immutable snapshots. Everything downstream (features, detectors, blast
radius) is computed from :class:`SnapshotDelta`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from cleanroom.domain.file_record import FileRecord


class ChangeType(str, Enum):
    """How a single file changed between two snapshots."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"  # content preserved, path (usually extension) changed


@dataclass(frozen=True, slots=True)
class FileChange:
    """One file's transition from the previous snapshot to the current one.

    ``before``/``after`` are the FileRecords on each side (``None`` where the
    file did not exist). ``entropy_delta`` is the headline forensic quantity: a
    large positive jump is the statistical signature of in-place encryption.
    """

    change_type: ChangeType
    path: str
    before: FileRecord | None
    after: FileRecord | None

    @property
    def entropy_delta(self) -> float:
        if self.before is None or self.after is None:
            return 0.0
        return self.after.entropy - self.before.entropy

    @property
    def size_delta(self) -> int:
        after = self.after.size if self.after else 0
        before = self.before.size if self.before else 0
        return after - before

    @property
    def affected_bytes(self) -> int:
        """Bytes considered 'at risk' from this change (for blast radius)."""
        if self.change_type is ChangeType.DELETED and self.before:
            return self.before.size
        if self.after:
            return self.after.size
        return 0


@dataclass(frozen=True, slots=True)
class SnapshotDelta:
    """All file-level changes between ``previous_id`` and ``current_id``."""

    previous_id: str | None
    current_id: str
    changes: tuple[FileChange, ...] = field(default_factory=tuple)
    prev_file_count: int = 0
    curr_file_count: int = 0
    seconds_elapsed: float = 0.0

    # --- convenient views ------------------------------------------------- #
    def of_type(self, change_type: ChangeType) -> tuple[FileChange, ...]:
        return tuple(c for c in self.changes if c.change_type is change_type)

    @property
    def added(self) -> tuple[FileChange, ...]:
        return self.of_type(ChangeType.ADDED)

    @property
    def modified(self) -> tuple[FileChange, ...]:
        return self.of_type(ChangeType.MODIFIED)

    @property
    def deleted(self) -> tuple[FileChange, ...]:
        return self.of_type(ChangeType.DELETED)

    @property
    def renamed(self) -> tuple[FileChange, ...]:
        return self.of_type(ChangeType.RENAMED)

    @property
    def total_changes(self) -> int:
        return len(self.changes)

    @property
    def is_empty(self) -> bool:
        return not self.changes
