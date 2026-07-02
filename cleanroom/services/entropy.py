"""Block-level Shannon entropy — the core of the file-content stage.

Encryption maximises information density: ciphertext is statistically
indistinguishable from random noise, so its byte distribution is nearly uniform
and its Shannon entropy approaches the 8.0 bits/byte ceiling. Ordinary files
(text, source, office documents, even most already-compressed media *headers*)
carry structure and sit lower. A sharp per-file entropy jump between snapshots is
therefore the classic signature of in-place encryption.

We sample a bounded number of fixed-size blocks so scanning a 4 GB file costs the
same as scanning a 4 KB one — essential for a tool that runs across an entire
backup estate.
"""

from __future__ import annotations

import math

from cleanroom.config import EntropyConfig


class EntropyCalculator:
    """Computes sampled Shannon entropy (bits/byte, 0..8) for byte content."""

    def __init__(self, config: EntropyConfig | None = None) -> None:
        self._config = config or EntropyConfig()

    # ------------------------------------------------------------------ #
    @staticmethod
    def _block_entropy(block: bytes) -> float:
        """Shannon entropy of a single block in bits per byte."""
        if not block:
            return 0.0
        counts = [0] * 256
        for byte in block:
            counts[byte] += 1
        length = len(block)
        entropy = 0.0
        for count in counts:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    # ------------------------------------------------------------------ #
    def of_bytes(self, data: bytes) -> float:
        """Mean block entropy over up to ``max_blocks`` evenly-spread blocks."""
        if not data:
            return 0.0

        block_size = self._config.block_size
        max_blocks = self._config.max_blocks

        n_blocks = max(1, math.ceil(len(data) / block_size))
        if n_blocks <= max_blocks:
            indices = range(n_blocks)
        else:
            # Evenly sample across the file so we don't just read the header.
            step = n_blocks / max_blocks
            indices = (int(i * step) for i in range(max_blocks))

        entropies = []
        for i in indices:
            start = i * block_size
            block = data[start : start + block_size]
            if block:
                entropies.append(self._block_entropy(block))

        return sum(entropies) / len(entropies) if entropies else 0.0

    def of_file(self, path: str) -> float:
        """Entropy of a file on disk (streamed, bounded by ``max_blocks``)."""
        block_size = self._config.block_size
        max_blocks = self._config.max_blocks
        entropies: list[float] = []
        with open(path, "rb") as fh:
            while len(entropies) < max_blocks:
                block = fh.read(block_size)
                if not block:
                    break
                entropies.append(self._block_entropy(block))
        return sum(entropies) / len(entropies) if entropies else 0.0
