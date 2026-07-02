"""Detection results: per-signal scores, per-snapshot verdicts, and the timeline.

Designed for *explainability* (Rubrik's Integrity + Transparency values): every
verdict carries the individual signal scores and human-readable evidence that
produced it, so an operator can see exactly why a snapshot was flagged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    """Escalating trust level for a single snapshot."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"

    @property
    def rank(self) -> int:
        return {"clean": 0, "suspicious": 1, "compromised": 2}[self.value]


@dataclass(frozen=True, slots=True)
class SignalScore:
    """One detector's contribution: a 0..1 score plus why it fired."""

    name: str
    score: float
    weight: float
    evidence: str

    @property
    def weighted(self) -> float:
        return self.score * self.weight


@dataclass(frozen=True, slots=True)
class SnapshotAssessment:
    """The verdict for a single snapshot and the signals behind it."""

    snapshot_id: str
    verdict: Verdict
    anomaly_score: float                     # fused 0..1
    signals: tuple[SignalScore, ...] = field(default_factory=tuple)
    label: str | None = None                 # ground truth (benchmark only)

    @property
    def top_signals(self) -> tuple[SignalScore, ...]:
        """Signals sorted by weighted contribution, strongest first."""
        return tuple(sorted(self.signals, key=lambda s: s.weighted, reverse=True))

    def explain(self) -> str:
        parts = [
            f"{s.name}={s.score:.2f} ({s.evidence})"
            for s in self.top_signals
            if s.score > 0.01
        ]
        return "; ".join(parts) if parts else "no significant signals"


@dataclass(frozen=True, slots=True)
class TimelineAssessment:
    """Ordered assessments for every snapshot in a timeline."""

    assessments: tuple[SnapshotAssessment, ...] = field(default_factory=tuple)

    def __iter__(self):
        return iter(self.assessments)

    def __len__(self) -> int:
        return len(self.assessments)

    def by_id(self, snapshot_id: str) -> SnapshotAssessment | None:
        return next(
            (a for a in self.assessments if a.snapshot_id == snapshot_id), None
        )

    @property
    def first_compromised(self) -> SnapshotAssessment | None:
        """Earliest snapshot judged COMPROMISED — the moment of infection."""
        return next(
            (a for a in self.assessments if a.verdict is Verdict.COMPROMISED), None
        )
