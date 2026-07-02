"""Heuristic detectors — each a Strategy producing one explainable SignalScore.

The engine holds a *list* of these. To add a new signal, implement
:class:`Detector` and register it — nothing else changes (Open/Closed).
"""

from cleanroom.detection.detectors.base import Detector
from cleanroom.detection.detectors.entropy_detector import EntropyDetector
from cleanroom.detection.detectors.velocity_detector import VelocityDetector
from cleanroom.detection.detectors.mass_ops_detector import MassOpsDetector
from cleanroom.detection.detectors.extension_detector import ExtensionDetector
from cleanroom.detection.detectors.canary_detector import CanaryDetector

__all__ = [
    "Detector",
    "EntropyDetector",
    "VelocityDetector",
    "MassOpsDetector",
    "ExtensionDetector",
    "CanaryDetector",
]
