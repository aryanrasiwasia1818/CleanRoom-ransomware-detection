"""A filesystem-backed, append-only snapshot repository.

Each snapshot is one JSON manifest named ``<id>.snapshot.json``. Timeline order
is the lexical order of the ids (zero-padded), so ``0001`` precedes ``0010``.

The repository refuses to overwrite an existing manifest — enforcing, in code,
the immutability guarantee that a real WORM/immutable backup enforces in
hardware. That's the whole premise CleanRoom's trust rests on.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from cleanroom.config import StorageConfig
from cleanroom.domain import Snapshot
from cleanroom.ports import SnapshotRepository


class FileSystemSnapshotRepository(SnapshotRepository):
    """Stores snapshots as immutable JSON manifests under a root directory."""

    def __init__(self, config: StorageConfig | None = None, root: str | None = None):
        cfg = config or StorageConfig()
        self._root = Path(root or cfg.root)
        self._suffix = cfg.manifest_suffix
        self._root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    def _path_for(self, snapshot_id: str) -> Path:
        return self._root / f"{snapshot_id}{self._suffix}"

    # ------------------------------------------------------------------ #
    def append(self, snapshot: Snapshot) -> None:
        target = self._path_for(snapshot.snapshot_id)
        if target.exists():
            raise FileExistsError(
                f"Snapshot {snapshot.snapshot_id!r} already exists; "
                "snapshots are immutable and cannot be overwritten."
            )
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot.to_dict(), indent=2))
        tmp.replace(target)  # atomic publish

    def get(self, snapshot_id: str) -> Snapshot:
        target = self._path_for(snapshot_id)
        if not target.exists():
            raise KeyError(snapshot_id)
        return Snapshot.from_dict(json.loads(target.read_text()))

    def list_ids(self) -> list[str]:
        ids = [
            p.name[: -len(self._suffix)]
            for p in self._root.glob(f"*{self._suffix}")
        ]
        return sorted(ids)

    def __iter__(self) -> Iterator[Snapshot]:
        for snapshot_id in self.list_ids():
            yield self.get(snapshot_id)
