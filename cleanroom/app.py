"""Application facade — the single entry point every interface calls.

`CleanRoomApp` wires the services, detection engine and recovery analyzer into
three high-level use cases: **simulate** a timeline, **analyze** a repository,
and **benchmark** detection quality. Keeping this orchestration in one Facade
means the CLI, the API and the tests all exercise identical logic — there is no
second, subtly-different code path.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from cleanroom.config import Config
from cleanroom.detection import DetectionEngine
from cleanroom.domain import (
    RecoveryPlan,
    Snapshot,
    SnapshotDelta,
    TimelineAssessment,
    Verdict,
)
from cleanroom.infrastructure import FileSystemSnapshotRepository
from cleanroom.ports import SnapshotRepository
from cleanroom.recovery import RecoveryAnalyzer
from cleanroom.services import FeatureExtractor, SnapshotDiffer
from cleanroom.simulator import TimelineSimulator, get_family


# --------------------------------------------------------------------------- #
# Report models
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AnalysisReport:
    """Everything an interface needs to render an analysis."""

    assessment: TimelineAssessment
    recovery_plan: RecoveryPlan
    deltas: list[SnapshotDelta]
    snapshots_meta: list[dict]

    def to_dict(self) -> dict:
        rows = []
        delta_by_id = {d.current_id: d for d in self.deltas}
        meta_by_id = {m["snapshot_id"]: m for m in self.snapshots_meta}
        for a in self.assessment:
            delta = delta_by_id.get(a.snapshot_id)
            meta = meta_by_id.get(a.snapshot_id, {})
            rows.append(
                {
                    "snapshot_id": a.snapshot_id,
                    "taken_at": meta.get("taken_at"),
                    "file_count": meta.get("file_count"),
                    "verdict": a.verdict.value,
                    "anomaly_score": a.anomaly_score,
                    "label": a.label,
                    "changes": delta.total_changes if delta else 0,
                    "added": len(delta.added) if delta else 0,
                    "modified": len(delta.modified) if delta else 0,
                    "deleted": len(delta.deleted) if delta else 0,
                    "renamed": len(delta.renamed) if delta else 0,
                    "signals": [
                        {
                            "name": s.name,
                            "score": round(s.score, 4),
                            "weight": s.weight,
                            "evidence": s.evidence,
                        }
                        for s in a.top_signals
                    ],
                    "explanation": a.explain(),
                }
            )
        rp = self.recovery_plan
        return {
            "timeline": rows,
            "recovery_plan": {
                "incident_detected": rp.incident_detected,
                "last_clean_snapshot_id": rp.last_clean_snapshot_id,
                "first_compromised_snapshot_id": rp.first_compromised_snapshot_id,
                "confidence": rp.confidence,
                "recommendation": rp.recommendation,
                "summary": rp.summary(),
                "blast_radius": {
                    "files_encrypted": rp.blast_radius.files_encrypted,
                    "files_deleted": rp.blast_radius.files_deleted,
                    "files_added": rp.blast_radius.files_added,
                    "files_renamed": rp.blast_radius.files_renamed,
                    "total_files_affected": rp.blast_radius.total_files_affected,
                    "bytes_affected": rp.blast_radius.bytes_affected,
                    "snapshots_impacted": rp.blast_radius.snapshots_impacted,
                    "affected_paths_sample": list(
                        rp.blast_radius.affected_paths_sample
                    ),
                },
            },
        }


@dataclass(frozen=True)
class BenchmarkReport:
    """Aggregate detection quality across many simulated timelines."""

    runs: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    per_family: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "runs": self.runs,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
            "confusion": {
                "tp": self.true_positives,
                "fp": self.false_positives,
                "tn": self.true_negatives,
                "fn": self.false_negatives,
            },
            "per_family": self.per_family,
        }


# --------------------------------------------------------------------------- #
# Facade
# --------------------------------------------------------------------------- #


class CleanRoomApp:
    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._differ = SnapshotDiffer()
        self._extractor = FeatureExtractor(
            self._config.detection, self._config.entropy
        )
        self._engine = DetectionEngine(self._config)
        self._recovery = RecoveryAnalyzer()

    # ------------------------------------------------------------------ #
    def repository(self, root: str) -> FileSystemSnapshotRepository:
        return FileSystemSnapshotRepository(self._config.storage, root=root)

    # ------------------------------------------------------------------ #
    def simulate(
        self,
        family_name: str,
        root: str,
        clean_snapshots: int = 4,
        scale: int = 6,
        seed: int | None = None,
    ):
        """Generate a labelled timeline into the repository at ``root``."""
        repo = self.repository(root)
        simulator = TimelineSimulator(config=self._config)
        return simulator.simulate(
            family=get_family(family_name),
            repository=repo,
            clean_snapshots=clean_snapshots,
            scale=scale,
            seed=seed,
        )

    # ------------------------------------------------------------------ #
    def analyze(self, repository: SnapshotRepository) -> AnalysisReport:
        """Run the full forensic pipeline over an ordered snapshot repository."""
        snapshots: list[Snapshot] = list(repository)
        deltas: list[SnapshotDelta] = []
        features = []
        labels: dict[str, str] = {}
        meta: list[dict] = []

        previous: Snapshot | None = None
        for snap in snapshots:
            delta = self._differ.diff(previous, snap)
            deltas.append(delta)
            features.append(self._extractor.extract(delta))
            if snap.label:
                labels[snap.snapshot_id] = snap.label
            meta.append(
                {
                    "snapshot_id": snap.snapshot_id,
                    "taken_at": snap.taken_at.isoformat(),
                    "file_count": snap.file_count,
                }
            )
            previous = snap

        assessment = self._engine.assess(features, labels=labels)
        recovery_plan = self._recovery.analyze(deltas, assessment)
        return AnalysisReport(
            assessment=assessment,
            recovery_plan=recovery_plan,
            deltas=deltas,
            snapshots_meta=meta,
        )

    # ------------------------------------------------------------------ #
    def analyze_path(self, root: str) -> AnalysisReport:
        return self.analyze(self.repository(root))

    # ------------------------------------------------------------------ #
    def benchmark(
        self,
        runs_per_family: int = 5,
        families: list[str] | None = None,
        scale: int = 5,
        clean_snapshots: int = 4,
        base_seed: int = 1000,
    ) -> BenchmarkReport:
        """Measure precision/recall over many fresh simulated timelines.

        A snapshot is a *positive* prediction if flagged (SUSPICIOUS or
        COMPROMISED) and a *positive* truth if its ground-truth label is
        "infected". This yields an honest, reproducible precision figure.
        """
        import tempfile

        family_names = families or ["lockbit", "intermittent", "wiper"]
        tp = fp = tn = fn = 0
        per_family: dict[str, dict] = {}

        for fam in family_names:
            f_tp = f_fp = f_tn = f_fn = 0
            for i in range(runs_per_family):
                with tempfile.TemporaryDirectory(prefix="cr_bench_") as tmp:
                    repo = FileSystemSnapshotRepository(root=f"{tmp}/snaps")
                    TimelineSimulator(config=self._config).simulate(
                        family=get_family(fam),
                        repository=repo,
                        clean_snapshots=clean_snapshots,
                        scale=scale,
                        seed=base_seed + i,
                        workdir=f"{tmp}/work",
                    )
                    report = self.analyze(repo)
                    for a in report.assessment:
                        predicted_positive = a.verdict is not Verdict.CLEAN
                        actual_positive = a.label == "infected"
                        if predicted_positive and actual_positive:
                            f_tp += 1
                        elif predicted_positive and not actual_positive:
                            f_fp += 1
                        elif not predicted_positive and actual_positive:
                            f_fn += 1
                        else:
                            f_tn += 1

            per_family[fam] = self._metrics(f_tp, f_fp, f_tn, f_fn)
            tp, fp, tn, fn = tp + f_tp, fp + f_fp, tn + f_tn, fn + f_fn

        overall = self._metrics(tp, fp, tn, fn)
        return BenchmarkReport(
            runs=len(family_names) * runs_per_family,
            precision=overall["precision"],
            recall=overall["recall"],
            f1=overall["f1"],
            accuracy=overall["accuracy"],
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            per_family=per_family,
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        }
