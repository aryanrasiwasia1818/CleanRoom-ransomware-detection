"""The atom of the model: a single file as captured in one snapshot."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class FileRecord:
    """Immutable metadata + content fingerprint for one file in one snapshot.

    We deliberately store *fingerprints* (a content hash + a sampled entropy
    value), never the file bytes. This is exactly the posture of a backup
    forensics tool: it reasons over metadata and statistical summaries of
    immutable data, so it can never itself become an exfiltration path.
    """

    path: str
    size: int
    content_hash: str
    entropy: float
    modified_ns: int

    # --- derived helpers (behaviour lives with the data) ------------------ #
    @property
    def extension(self) -> str:
        """Lower-cased final suffix, e.g. ``.docx`` ("" if none)."""
        return PurePosixPath(self.path).suffix.lower()

    @property
    def stem(self) -> str:
        """Filename without its final suffix (used to spot rename+encrypt)."""
        p = PurePosixPath(self.path)
        return str(p.with_suffix(""))

    def is_high_entropy(self, threshold: float) -> bool:
        return self.entropy >= threshold

    # --- (de)serialisation ------------------------------------------------ #
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "FileRecord":
        return cls(
            path=data["path"],
            size=int(data["size"]),
            content_hash=data["content_hash"],
            entropy=float(data["entropy"]),
            modified_ns=int(data["modified_ns"]),
        )
