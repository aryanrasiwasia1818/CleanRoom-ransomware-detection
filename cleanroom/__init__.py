"""CleanRoom — a ransomware-resilience engine built on immutable snapshots.

CleanRoom performs *storage forensics* (not endpoint agent telemetry). It reads
the deltas between successive backup snapshots, scores each snapshot for signs of
ransomware, then pinpoints the last clean recovery point and computes the blast
radius across the backup timeline.

The public surface is intentionally small; see :mod:`cleanroom.app` for the
high-level facade used by every interface (CLI, API, dashboard).
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
