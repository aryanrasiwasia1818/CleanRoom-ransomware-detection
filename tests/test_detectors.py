"""Unit tests for individual heuristic detectors (Strategy objects)."""

from cleanroom.config import DetectionConfig
from cleanroom.detection.baseline import BaselineStats
from cleanroom.detection.detectors import (
    CanaryDetector,
    EntropyDetector,
    ExtensionDetector,
    MassOpsDetector,
)
from cleanroom.domain import FeatureVector

BASELINE = BaselineStats(velocity_mean=0.001, velocity_std=0.0005, sample_size=3)


def _fv(**over):
    base = dict(
        snapshot_id="0001", change_ratio=0.0, add_ratio=0.0, delete_ratio=0.0,
        modify_ratio=0.0, rename_ratio=0.0, change_velocity=0.0,
        mean_entropy_delta=0.0, max_entropy_delta=0.0, high_entropy_fraction=0.0,
        suspicious_ext_fraction=0.0, distinct_new_extensions=0, canary_touched=0,
    )
    base.update(over)
    return FeatureVector(**base)


def test_entropy_detector_fires_on_broad_high_entropy():
    d = EntropyDetector(DetectionConfig())
    s = d.evaluate(_fv(high_entropy_fraction=0.9, mean_entropy_delta=3.5), BASELINE)
    assert s.score > 0.9


def test_entropy_detector_quiet_on_normal_edits():
    d = EntropyDetector(DetectionConfig())
    s = d.evaluate(_fv(high_entropy_fraction=0.0, mean_entropy_delta=0.1), BASELINE)
    assert s.score < 0.1


def test_mass_ops_detector_fires_on_mass_delete():
    d = MassOpsDetector(DetectionConfig())
    s = d.evaluate(_fv(delete_ratio=0.5), BASELINE)
    assert s.score > 0.9


def test_extension_detector_fires_on_suspicious_ext():
    d = ExtensionDetector(DetectionConfig())
    s = d.evaluate(_fv(suspicious_ext_fraction=0.5), BASELINE)
    assert s.score > 0.9


def test_canary_detector_is_binary():
    d = CanaryDetector(DetectionConfig())
    assert d.evaluate(_fv(canary_touched=0), BASELINE).score == 0.0
    assert d.evaluate(_fv(canary_touched=1), BASELINE).score == 1.0
