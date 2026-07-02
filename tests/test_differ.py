"""SnapshotDiffer: correct classification of every change type."""

from datetime import datetime, timedelta, timezone

from cleanroom.domain import ChangeType, FileRecord, Snapshot
from cleanroom.services import SnapshotDiffer

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _rec(path, h, entropy=4.0, size=1000):
    return FileRecord(path=path, size=size, content_hash=h, entropy=entropy, modified_ns=1)


def _snap(sid, records, offset_days=0):
    return Snapshot.create(sid, "src", records, taken_at=T0 + timedelta(days=offset_days))


def test_first_snapshot_is_all_added():
    s = _snap("0001", [_rec("a.txt", "h1"), _rec("b.txt", "h2")])
    delta = SnapshotDiffer().diff(None, s)
    assert delta.previous_id is None
    assert len(delta.added) == 2 and delta.total_changes == 2


def test_modified_detected_by_hash_change():
    a = _snap("0001", [_rec("a.txt", "h1", entropy=4.0)])
    b = _snap("0002", [_rec("a.txt", "h2", entropy=7.9)], offset_days=1)
    delta = SnapshotDiffer().diff(a, b)
    assert len(delta.modified) == 1
    assert abs(delta.modified[0].entropy_delta - 3.9) < 1e-6


def test_pure_rename_detected_by_identical_hash():
    a = _snap("0001", [_rec("a.txt", "h1")])
    b = _snap("0002", [_rec("a_renamed.txt", "h1")], offset_days=1)
    delta = SnapshotDiffer().diff(a, b)
    assert len(delta.renamed) == 1
    assert not delta.deleted and not delta.added


def test_encrypt_and_rename_becomes_modified_with_entropy_jump():
    # report.txt (low entropy) -> report.txt.lockbit (high entropy, new hash)
    a = _snap("0001", [_rec("report.txt", "h1", entropy=4.2)])
    b = _snap("0002", [_rec("report.txt.lockbit", "h2", entropy=7.95)], offset_days=1)
    delta = SnapshotDiffer().diff(a, b)
    assert len(delta.modified) == 1
    change = delta.modified[0]
    assert change.change_type is ChangeType.MODIFIED
    assert change.entropy_delta > 3.0
    assert change.after.extension == ".lockbit"


def test_true_delete_and_add():
    a = _snap("0001", [_rec("a.txt", "h1"), _rec("b.txt", "h2")])
    b = _snap("0002", [_rec("b.txt", "h2"), _rec("c.txt", "h3")], offset_days=1)
    delta = SnapshotDiffer().diff(a, b)
    assert len(delta.deleted) == 1 and delta.deleted[0].path == "a.txt"
    assert len(delta.added) == 1 and delta.added[0].path == "c.txt"
