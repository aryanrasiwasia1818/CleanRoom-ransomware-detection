"""Builds and evolves a realistic clean file corpus on disk.

The corpus mixes low-entropy content (text, source, csv, config) with a few
naturally *high*-entropy files (pseudo-jpeg / zip blobs). Including the latter is
deliberate: it proves the detector keys on the entropy *jump between snapshots*,
not on absolute entropy, so pre-existing compressed files don't trigger false
positives.
"""

from __future__ import annotations

import random
import string
from pathlib import Path

_WORDS = (
    "invoice payment ledger account customer report quarter revenue expense "
    "vendor contract policy renewal balance transfer receipt statement audit "
    "budget forecast summary meeting notes action item owner deadline status "
    "the a of to and in for with on at by from into over under between backup "
    "snapshot recovery resilience data secure integrity velocity excellence"
).split()


def _lorem(rng: random.Random, n_words: int) -> str:
    return " ".join(rng.choice(_WORDS) for _ in range(n_words))


def _text_blob(rng: random.Random, kb: int) -> bytes:
    """Human-like text — naturally low entropy (~4-5 bits/byte)."""
    target = kb * 1024
    chunks: list[str] = []
    size = 0
    while size < target:
        line = _lorem(rng, rng.randint(8, 16)) + "\n"
        chunks.append(line)
        size += len(line)
    return "".join(chunks).encode("utf-8")


def _code_blob(rng: random.Random, kb: int) -> bytes:
    target = kb * 1024
    lines: list[str] = []
    size = 0
    while size < target:
        name = "".join(rng.choice(string.ascii_lowercase) for _ in range(6))
        line = f"def {name}(x):\n    return x * {rng.randint(1, 99)}  # {_lorem(rng, 4)}\n"
        lines.append(line)
        size += len(line)
    return "".join(lines).encode("utf-8")


def _high_entropy_blob(rng: random.Random, kb: int) -> bytes:
    """Already-compressed/encrypted-looking content (~8 bits/byte)."""
    return bytes(rng.getrandbits(8) for _ in range(kb * 1024))


# Corpus template: (relative dir, base name, extension, kind, size_kb)
_TEMPLATE = [
    ("finance", "q{}_invoice", ".txt", "text", 6),
    ("finance", "ledger_{}", ".csv", "text", 8),
    ("finance", "budget_{}", ".txt", "text", 5),
    ("hr", "policy_{}", ".md", "text", 4),
    ("hr", "onboarding_{}", ".txt", "text", 3),
    ("engineering", "service_{}", ".py", "code", 7),
    ("engineering", "handler_{}", ".py", "code", 6),
    ("engineering", "config_{}", ".json", "text", 2),
    ("reports", "summary_{}", ".md", "text", 5),
    ("media", "photo_{}", ".jpg", "high", 10),   # naturally high entropy
    ("archives", "backup_{}", ".zip", "high", 12),  # naturally high entropy
]


def build_corpus(
    root: str | Path,
    rng: random.Random,
    scale: int = 6,
    canary_names: tuple[str, ...] = (),
) -> int:
    """Create a fresh corpus under ``root``. Returns the number of files written."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    count = 0
    for subdir, base, ext, kind, kb in _TEMPLATE:
        (root / subdir).mkdir(parents=True, exist_ok=True)
        for i in range(1, scale + 1):
            name = base.format(i) + ext
            path = root / subdir / name
            jitter = rng.randint(0, 2)
            if kind == "text":
                data = _text_blob(rng, kb + jitter)
            elif kind == "code":
                data = _code_blob(rng, kb + jitter)
            else:
                data = _high_entropy_blob(rng, kb + jitter)
            path.write_bytes(data)
            count += 1

    # Plant canary / decoy files at the corpus root.
    for canary in canary_names:
        (root / canary).write_bytes(_text_blob(rng, 2))
        count += 1

    return count


def apply_benign_churn(root: str | Path, rng: random.Random) -> None:
    """Simulate a day of ordinary user activity between snapshots.

    A handful of text/code files are edited (staying low entropy), maybe one new
    file appears, maybe one is removed. This is the 'normal' the baseline learns.
    """
    root = Path(root)
    editable = [
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix in (".txt", ".md", ".csv", ".py", ".json")
    ]
    rng.shuffle(editable)

    # Edit ~5-12% of editable files with more text (low entropy preserved).
    n_edit = max(1, int(len(editable) * rng.uniform(0.05, 0.12)))
    for path in editable[:n_edit]:
        with path.open("ab") as fh:
            fh.write(b"\n" + _lorem(rng, rng.randint(20, 60)).encode("utf-8"))

    # Occasionally add a new report.
    if rng.random() < 0.5:
        newp = root / "reports" / f"note_{rng.randint(1000, 9999)}.md"
        newp.write_bytes(_text_blob(rng, rng.randint(2, 5)))

    # Occasionally remove one file (normal cleanup).
    if rng.random() < 0.3 and len(editable) > n_edit + 1:
        editable[n_edit].unlink(missing_ok=True)
