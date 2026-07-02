"""SnapshotCapturer — turns a directory tree into an immutable Snapshot.

This is the software stand-in for a backup appliance taking a snapshot: it walks
a protected path and records, per file, a content hash and a sampled entropy
value (plus size + mtime). It never keeps file bytes.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from cleanroom.config import EntropyConfig
from cleanroom.domain import FileRecord, Snapshot
from cleanroom.services.entropy import EntropyCalculator


class SnapshotCapturer:
    """Walks a directory and produces a :class:`Snapshot`."""

    def __init__(
        self,
        entropy_config: EntropyConfig | None = None,
        entropy_calculator: EntropyCalculator | None = None,
    ) -> None:
        # Allow the calculator to be injected (testability / DIP).
        self._entropy = entropy_calculator or EntropyCalculator(entropy_config)

    # ------------------------------------------------------------------ #
    def _hash_and_entropy(self, path: Path, block_size: int) -> tuple[str, float]:
        """Single pass over the file: content hash + entropy from same blocks."""
        hasher = hashlib.sha256()
        entropies: list[float] = []
        max_blocks = self._entropy._config.max_blocks  # noqa: SLF001 (same pkg)
        with path.open("rb") as fh:
            block_index = 0
            while True:
                block = fh.read(block_size)
                if not block:
                    break
                hasher.update(block)
                if block_index < max_blocks:
                    entropies.append(EntropyCalculator._block_entropy(block))
                block_index += 1
        entropy = sum(entropies) / len(entropies) if entropies else 0.0
        return hasher.hexdigest(), entropy

    # ------------------------------------------------------------------ #
    def capture(
        self,
        source_dir: str | os.PathLike,
        snapshot_id: str,
        taken_at: datetime | None = None,
        label: str | None = None,
    ) -> Snapshot:
        """Capture ``source_dir`` into a snapshot with the given id."""
        root = Path(source_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"Not a directory: {root}")

        block_size = self._entropy._config.block_size  # noqa: SLF001
        records: list[FileRecord] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                stat = path.stat()
                content_hash, entropy = self._hash_and_entropy(path, block_size)
            except OSError:
                continue  # unreadable file — skip, don't crash the capture
            rel = path.relative_to(root).as_posix()
            records.append(
                FileRecord(
                    path=rel,
                    size=stat.st_size,
                    content_hash=content_hash,
                    entropy=round(entropy, 4),
                    modified_ns=stat.st_mtime_ns,
                )
            )

        return Snapshot.create(
            snapshot_id=snapshot_id,
            source=str(root),
            records=records,
            taken_at=taken_at or datetime.now(timezone.utc),
            label=label,
        )
