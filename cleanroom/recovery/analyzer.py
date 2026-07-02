"""RecoveryAnalyzer — turns detections into an actionable recovery plan.

Two questions matter after an alert, and both are what set a data-security
platform apart from a mere alerting tool:

1. **Last clean recovery point** — the newest snapshot before the attack that we
   still trust. Recovering from it minimises data loss.
2. **Blast radius** — everything the attack touched from the infection point
   onward, so responders know the scope before they act.
"""

from __future__ import annotations

from cleanroom.domain import (
    BlastRadius,
    ChangeType,
    RecoveryPlan,
    SnapshotDelta,
    TimelineAssessment,
    Verdict,
)

_SAMPLE_LIMIT = 20


class RecoveryAnalyzer:
    """Derives a :class:`RecoveryPlan` from deltas + a timeline assessment."""

    def analyze(
        self,
        deltas: list[SnapshotDelta],
        assessment: TimelineAssessment,
    ) -> RecoveryPlan:
        ordered_ids = [d.current_id for d in deltas]
        first_compromised = assessment.first_compromised

        if first_compromised is None:
            # Clean timeline — recommend the most recent snapshot.
            latest = ordered_ids[-1] if ordered_ids else None
            return RecoveryPlan(
                incident_detected=False,
                last_clean_snapshot_id=latest,
                first_compromised_snapshot_id=None,
                blast_radius=BlastRadius(),
                recommendation=(
                    "No ransomware indicators found. Latest snapshot "
                    f"{latest} is safe to use." if latest else "No snapshots."
                ),
                confidence=self._clean_confidence(assessment),
            )

        infection_id = first_compromised.snapshot_id
        infection_idx = ordered_ids.index(infection_id)
        last_clean = self._last_clean_before(ordered_ids, infection_idx, assessment)
        blast = self._blast_radius(deltas[infection_idx:], assessment)

        recommendation = (
            f"Isolate affected systems, then restore from snapshot "
            f"{last_clean} (last verified-clean point). Do NOT restore from "
            f"{infection_id} or later — those carry attacker changes."
            if last_clean
            else "No clean snapshot exists in the retained timeline; escalate — "
            "the earliest available snapshot may already be compromised."
        )

        return RecoveryPlan(
            incident_detected=True,
            last_clean_snapshot_id=last_clean,
            first_compromised_snapshot_id=infection_id,
            blast_radius=blast,
            recommendation=recommendation,
            confidence=round(first_compromised.anomaly_score, 4),
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _last_clean_before(
        ordered_ids: list[str], infection_idx: int, assessment: TimelineAssessment
    ) -> str | None:
        """Newest CLEAN snapshot strictly before the infection index."""
        for idx in range(infection_idx - 1, -1, -1):
            a = assessment.by_id(ordered_ids[idx])
            if a and a.verdict is Verdict.CLEAN:
                return ordered_ids[idx]
        return None

    # ------------------------------------------------------------------ #
    @staticmethod
    def _blast_radius(
        deltas_from_infection: list[SnapshotDelta], assessment: TimelineAssessment
    ) -> BlastRadius:
        encrypted = deleted = added = renamed = 0
        bytes_affected = 0
        impacted_snapshots = 0
        sample: list[str] = []

        for delta in deltas_from_infection:
            a = assessment.by_id(delta.current_id)
            if a and a.verdict is not Verdict.CLEAN:
                impacted_snapshots += 1
            for change in delta.changes:
                if change.change_type is ChangeType.MODIFIED:
                    encrypted += 1
                elif change.change_type is ChangeType.DELETED:
                    deleted += 1
                elif change.change_type is ChangeType.RENAMED:
                    renamed += 1
                elif change.change_type is ChangeType.ADDED:
                    added += 1
                bytes_affected += change.affected_bytes
                if len(sample) < _SAMPLE_LIMIT and change.change_type is not ChangeType.ADDED:
                    sample.append(change.path)

        return BlastRadius(
            files_encrypted=encrypted,
            files_deleted=deleted,
            files_added=added,
            files_renamed=renamed,
            bytes_affected=bytes_affected,
            snapshots_impacted=impacted_snapshots,
            affected_paths_sample=tuple(sample),
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _clean_confidence(assessment: TimelineAssessment) -> float:
        """How confident we are the timeline is clean (1 - worst score)."""
        if not len(assessment):
            return 0.0
        worst = max(a.anomaly_score for a in assessment)
        return round(1.0 - worst, 4)
