"""Entropy calculator: the numeric backbone of the content-analysis stage."""

import random

from cleanroom.services import EntropyCalculator


def test_random_bytes_are_near_maximum_entropy():
    rng = random.Random(1)
    data = bytes(rng.getrandbits(8) for _ in range(8192))
    assert EntropyCalculator().of_bytes(data) > 7.5


def test_text_is_low_entropy():
    data = ("the quick brown fox jumps over the lazy dog " * 400).encode()
    assert EntropyCalculator().of_bytes(data) < 5.0


def test_empty_is_zero():
    assert EntropyCalculator().of_bytes(b"") == 0.0


def test_single_byte_repeated_is_zero_entropy():
    assert EntropyCalculator().of_bytes(b"\x00" * 4096) == 0.0


def test_encryption_raises_entropy_of_text():
    calc = EntropyCalculator()
    text = ("invoice payment ledger account " * 500).encode()
    rng = random.Random(2)
    cipher = bytes(rng.getrandbits(8) for _ in range(len(text)))
    assert calc.of_bytes(cipher) - calc.of_bytes(text) > 2.5
