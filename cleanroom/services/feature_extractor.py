"""FeatureExtractor — turns a raw SnapshotDelta into a numeric FeatureVector.

This is the boundary between "what happened" (domain deltas) and "how do we
score it" (detection). Extracting features once, here, guarantees the heuristics
and the ML model see identical inputs.
"""

from __future__ import annotations

from cleanroom.config import DetectionConfig, EntropyConfig
from cleanroom.domain import ChangeType, FeatureVector, SnapshotDelta


class FeatureExtractor:
    """Computes a :class:`FeatureVector` from a :class:`SnapshotDelta`."""

    def __init__(
        self,
        detection_config: DetectionConfig | None = None,
        entropy_config: EntropyConfig | None = None,
    ) -> None:
        self._dcfg = detection_config or DetectionConfig()
        self._ecfg = entropy_config or EntropyConfig()

    # ------------------------------------------------------------------ #
    def extract(self, delta: SnapshotDelta) -> FeatureVector:
        # Genesis snapshot: no previous state exists, so there is no "change" to
        # reason about. Emit a neutral (all-zero) vector so it can never look
        # anomalous and never distorts the learned baseline.
        if delta.previous_id is None:
            return FeatureVector(
                snapshot_id=delta.current_id,
                change_ratio=0.0, add_ratio=0.0, delete_ratio=0.0,
                modify_ratio=0.0, rename_ratio=0.0, change_velocity=0.0,
                mean_entropy_delta=0.0, max_entropy_delta=0.0,
                high_entropy_fraction=0.0, suspicious_ext_fraction=0.0,
                distinct_new_extensions=0, canary_touched=0,
            )

        base = max(1, delta.prev_file_count)  # avoid div-by-zero
        n_changes = delta.total_changes

        added = delta.added
        deleted = delta.deleted
        modified = delta.modified
        renamed = delta.renamed

        # --- velocity ----------------------------------------------------- #
        if delta.seconds_elapsed > 0:
            velocity = n_changes / delta.seconds_elapsed
        else:
            velocity = float(n_changes)  # unknown cadence: use raw count

        # --- entropy over content-changing files -------------------------- #
        content_changes = [*modified, *renamed]
        entropy_deltas = [c.entropy_delta for c in content_changes]
        high_thr = self._ecfg.high_entropy_threshold
        high_entropy_hits = sum(
            1
            for c in content_changes
            if c.after is not None and c.after.entropy >= high_thr
        )
        mean_ed = (
            sum(entropy_deltas) / len(entropy_deltas) if entropy_deltas else 0.0
        )
        max_ed = max(entropy_deltas, default=0.0)
        high_entropy_fraction = (
            high_entropy_hits / len(content_changes) if content_changes else 0.0
        )

        # --- extensions --------------------------------------------------- #
        suspicious = set(self._dcfg.suspicious_extensions)
        new_ext_hits = 0
        new_extensions: set[str] = set()
        for c in (*added, *renamed, *modified):
            if c.after is None:
                continue
            ext = c.after.extension
            if c.change_type in (ChangeType.ADDED, ChangeType.RENAMED):
                new_extensions.add(ext)
            if ext in suspicious:
                new_ext_hits += 1
        suspicious_ext_fraction = new_ext_hits / max(1, n_changes)

        # --- canaries ----------------------------------------------------- #
        canary_set = set(self._dcfg.canary_filenames)
        canary_touched = sum(
            1
            for c in delta.changes
            if c.path.split("/")[-1] in canary_set
            and c.change_type is not ChangeType.ADDED
        )

        return FeatureVector(
            snapshot_id=delta.current_id,
            change_ratio=n_changes / base,
            add_ratio=len(added) / base,
            delete_ratio=len(deleted) / base,
            modify_ratio=len(modified) / base,
            rename_ratio=len(renamed) / base,
            change_velocity=velocity,
            mean_entropy_delta=mean_ed,
            max_entropy_delta=max_ed,
            high_entropy_fraction=high_entropy_fraction,
            suspicious_ext_fraction=suspicious_ext_fraction,
            distinct_new_extensions=len(new_extensions),
            canary_touched=canary_touched,
        )
