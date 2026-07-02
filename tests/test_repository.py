"""FileSystemSnapshotRepository: ordering + the immutability guarantee."""

import pytest

from cleanroom.domain import FileRecord, Snapshot
from cleanroom.infrastructure import FileSystemSnapshotRepository


def _snap(sid):
    rec = FileRecord("a.txt", 10, "h", 4.0, 1)
    return Snapshot.create(sid, "src", [rec])


def test_append_get_roundtrip(tmp_path):
    repo = FileSystemSnapshotRepository(root=str(tmp_path))
    repo.append(_snap("0001"))
    loaded = repo.get("0001")
    assert loaded.snapshot_id == "0001"
    assert loaded.files["a.txt"].content_hash == "h"


def test_snapshots_are_immutable(tmp_path):
    repo = FileSystemSnapshotRepository(root=str(tmp_path))
    repo.append(_snap("0001"))
    with pytest.raises(FileExistsError):
        repo.append(_snap("0001"))  # overwriting is forbidden


def test_iteration_is_timeline_ordered(tmp_path):
    repo = FileSystemSnapshotRepository(root=str(tmp_path))
    for sid in ["0002", "0010", "0001"]:
        repo.append(_snap(sid))
    assert [s.snapshot_id for s in repo] == ["0001", "0002", "0010"]
    assert len(repo) == 3
