"""End-to-end: simulate a real attack on disk, then analyze it.

These are the highest-value tests — they exercise capture → diff → features →
detection → recovery exactly as the CLI does.
"""

import pytest

from cleanroom.app import CleanRoomApp
from cleanroom.domain import Verdict
from cleanroom.infrastructure import FileSystemSnapshotRepository
from cleanroom.simulator import TimelineSimulator, get_family


def _run(family_name, tmp_path, seed=7, scale=5):
    repo = FileSystemSnapshotRepository(root=str(tmp_path / "snaps"))
    TimelineSimulator().simulate(
        family=get_family(family_name), repository=repo,
        clean_snapshots=4, scale=scale, seed=seed, workdir=str(tmp_path / "work"),
    )
    return CleanRoomApp().analyze(repo)


@pytest.mark.parametrize("family", ["lockbit", "intermittent", "wiper"])
def test_attack_is_detected(family, tmp_path):
    report = _run(family, tmp_path)
    assert report.recovery_plan.incident_detected, f"{family} not detected"


@pytest.mark.parametrize("family", ["lockbit", "intermittent", "wiper"])
def test_clean_snapshots_are_not_flagged(family, tmp_path):
    report = _run(family, tmp_path)
    for a in report.assessment:
        if a.label == "clean":
            assert a.verdict is Verdict.CLEAN, (
                f"false positive on clean snapshot {a.snapshot_id} "
                f"(score {a.anomaly_score})"
            )


def test_last_clean_point_precedes_infection(tmp_path):
    report = _run("lockbit", tmp_path)
    rp = report.recovery_plan
    assert rp.last_clean_snapshot_id is not None
    assert rp.last_clean_snapshot_id < rp.first_compromised_snapshot_id


def test_blast_radius_is_populated(tmp_path):
    report = _run("lockbit", tmp_path)
    br = report.recovery_plan.blast_radius
    assert br.total_files_affected > 0
    assert br.bytes_affected > 0


def test_last_clean_snapshot_is_the_one_before_infection(tmp_path):
    report = _run("lockbit", tmp_path)
    rp = report.recovery_plan
    ids = [a.snapshot_id for a in report.assessment]
    idx_clean = ids.index(rp.last_clean_snapshot_id)
    idx_infect = ids.index(rp.first_compromised_snapshot_id)
    assert idx_infect == idx_clean + 1
