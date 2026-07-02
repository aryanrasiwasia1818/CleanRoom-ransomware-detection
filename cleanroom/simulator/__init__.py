"""Ransomware simulator — generates realistic, *labelled* backup timelines.

There is no real backup estate to point at in a demo, so this package builds
one: a believable file corpus, several clean snapshots with benign user churn,
then an attack from a chosen ransomware *family*. Because the simulator knows the
ground truth, it lets us measure detection precision/recall honestly
(see ``cleanroom benchmark``).

Families are pluggable via the Strategy pattern (:class:`RansomwareFamily`), so a
new strain is a new subclass — no change to the timeline engine (Open/Closed).
"""

from cleanroom.simulator.families import (
    RansomwareFamily,
    LockBitStyleFamily,
    IntermittentEncryptorFamily,
    WiperFamily,
    FAMILIES,
    get_family,
)
from cleanroom.simulator.timeline import TimelineSimulator, SimulationResult

__all__ = [
    "RansomwareFamily",
    "LockBitStyleFamily",
    "IntermittentEncryptorFamily",
    "WiperFamily",
    "FAMILIES",
    "get_family",
    "TimelineSimulator",
    "SimulationResult",
]
