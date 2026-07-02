"""Orchestrates a full labelled timeline: clean history → attack → aftermath."""

from __future__ import annotations

import random
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cleanroom.config import Config
from cleanroom.domain import Snapshot
from cleanroom.ports import SnapshotRepository
from cleanroom.services import SnapshotCapturer
from cleanroom.simulator.corpus import apply_benign_churn, build_corpus
from cleanroom.simulator.families import RansomwareFamily

_BASE_TIME = datetime(2026, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
_CADENCE = timedelta(days=1)  # one backup per day


@dataclass(frozen=True)
class SimulationResult:
    """Ground-truth record of a simulated timeline (used for benchmarking)."""

    family_name: str
    clean_ids: list[str] = field(default_factory=list)
    infected_ids: list[str] = field(default_factory=list)
    first_infected_id: str | None = None
    workdir: str = ""


class TimelineSimulator:
    """Builds a corpus, snapshots benign history, then injects an attack."""

    def __init__(
        self,
        capturer: SnapshotCapturer | None = None,
        config: Config | None = None,
    ) -> None:
        self._config = config or Config()
        self._capturer = capturer or SnapshotCapturer(self._config.entropy)

    # ------------------------------------------------------------------ #
    def simulate(
        self,
        family: RansomwareFamily,
        repository: SnapshotRepository,
        clean_snapshots: int = 4,
        scale: int = 6,
        seed: int | None = None,
        workdir: str | None = None,
    ) -> SimulationResult:
        """Generate and persist a full timeline into ``repository``.

        Parameters
        ----------
        family:            the strain to inject after the clean history.
        clean_snapshots:   how many benign snapshots precede the attack.
        scale:             corpus size multiplier (files per template row).
        seed:              RNG seed for reproducibility.
        workdir:           where the live corpus is materialised (temp if None).
        """
        rng = random.Random(seed)
        work = Path(workdir or tempfile.mkdtemp(prefix="cleanroom_sim_"))
        work.mkdir(parents=True, exist_ok=True)

        canary = self._config.detection.canary_filenames
        build_corpus(work, rng, scale=scale, canary_names=canary)

        clean_ids: list[str] = []
        infected_ids: list[str] = []
        index = 0

        def _capture(label: str) -> Snapshot:
            nonlocal index
            index += 1
            snap = self._capturer.capture(
                work,
                snapshot_id=f"{index:04d}",
                taken_at=_BASE_TIME + _CADENCE * (index - 1),
                label=label,
            )
            repository.append(snap)
            return snap

        # --- clean history ------------------------------------------------ #
        first = _capture("clean")
        clean_ids.append(first.snapshot_id)
        for _ in range(clean_snapshots - 1):
            apply_benign_churn(work, rng)
            clean_ids.append(_capture("clean").snapshot_id)

        # --- attack ------------------------------------------------------- #
        for stage in range(family.stages):
            family.run_stage(work, rng, stage)
            infected_ids.append(_capture("infected").snapshot_id)

        return SimulationResult(
            family_name=family.name,
            clean_ids=clean_ids,
            infected_ids=infected_ids,
            first_infected_id=infected_ids[0] if infected_ids else None,
            workdir=str(work),
        )
