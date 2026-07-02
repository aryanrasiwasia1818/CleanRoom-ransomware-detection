"""SnapshotDiffer — computes the delta between two snapshots.

Diffing is a set operation on paths, refined by three matching passes so the
delta reflects what an attacker *actually did*, not just raw path churn:

1. **Pure rename** — a DELETE and an ADD with an *identical content hash* is a
   move/rename (content preserved). Rare for ransomware, but correct to model.
2. **Encrypt-and-rename** — a DELETE of ``report.txt`` and an ADD of
   ``report.txt.lockbit`` (added path == deleted path + a new suffix) is the
   signature of rename+encrypt families. Content differs, so we classify it as a
   MODIFIED file (old→new), which preserves the all-important entropy jump
   instead of hiding it as an unrelated delete+add.
3. **In-place** — remaining common paths whose content hash changed are
   MODIFIED; leftover adds/deletes are true adds/deletes.
"""

from __future__ import annotations

from cleanroom.domain import ChangeType, FileChange, Snapshot, SnapshotDelta


class SnapshotDiffer:
    """Pure function object producing a :class:`SnapshotDelta`."""

    def diff(self, previous: Snapshot | None, current: Snapshot) -> SnapshotDelta:
        if previous is None:
            changes = tuple(
                FileChange(ChangeType.ADDED, r.path, None, r)
                for r in current.files.values()
            )
            return SnapshotDelta(
                previous_id=None,
                current_id=current.snapshot_id,
                changes=changes,
                prev_file_count=0,
                curr_file_count=current.file_count,
                seconds_elapsed=0.0,
            )

        prev_files = previous.files
        curr_files = current.files
        raw_added = set(curr_files) - set(prev_files)
        raw_deleted = set(prev_files) - set(curr_files)
        common = set(prev_files) & set(curr_files)

        changes: list[FileChange] = []
        matched_del: set[str] = set()
        matched_add: set[str] = set()

        # --- pass 1: pure rename (identical content hash) ----------------- #
        deleted_by_hash: dict[str, list[str]] = {}
        for path in raw_deleted:
            deleted_by_hash.setdefault(prev_files[path].content_hash, []).append(path)
        for add_path in raw_added:
            candidates = deleted_by_hash.get(curr_files[add_path].content_hash)
            if candidates:
                old_path = candidates.pop()
                matched_del.add(old_path)
                matched_add.add(add_path)
                changes.append(
                    FileChange(
                        ChangeType.RENAMED, add_path, prev_files[old_path],
                        curr_files[add_path],
                    )
                )

        # --- pass 2: encrypt-and-rename (added == deleted + new suffix) --- #
        remaining_deleted = sorted(raw_deleted - matched_del, key=len, reverse=True)
        for add_path in sorted(raw_added - matched_add):
            for old_path in remaining_deleted:
                if old_path in matched_del:
                    continue
                tail = add_path[len(old_path):]
                if add_path.startswith(old_path) and tail.startswith("."):
                    matched_del.add(old_path)
                    matched_add.add(add_path)
                    changes.append(
                        FileChange(
                            ChangeType.MODIFIED, add_path, prev_files[old_path],
                            curr_files[add_path],
                        )
                    )
                    break

        # --- pass 3: true adds / deletes ---------------------------------- #
        for path in raw_added - matched_add:
            changes.append(FileChange(ChangeType.ADDED, path, None, curr_files[path]))
        for path in raw_deleted - matched_del:
            changes.append(
                FileChange(ChangeType.DELETED, path, prev_files[path], None)
            )

        # --- in-place modifications --------------------------------------- #
        for path in common:
            before, after = prev_files[path], curr_files[path]
            if before.content_hash != after.content_hash:
                changes.append(FileChange(ChangeType.MODIFIED, path, before, after))

        seconds = max(0.0, (current.taken_at - previous.taken_at).total_seconds())
        return SnapshotDelta(
            previous_id=previous.snapshot_id,
            current_id=current.snapshot_id,
            changes=tuple(changes),
            prev_file_count=previous.file_count,
            curr_file_count=current.file_count,
            seconds_elapsed=seconds,
        )
