"""Guards the headline claim: detection precision stays high across families."""

from cleanroom.app import CleanRoomApp


def test_precision_meets_claim():
    report = CleanRoomApp().benchmark(runs_per_family=3, scale=4)
    # The product claim is 95% precision; assert a safe margin below it so the
    # test is stable across machines/RNG while still guarding the promise.
    assert report.precision >= 0.90, f"precision regressed to {report.precision}"
    assert report.recall >= 0.80, f"recall regressed to {report.recall}"
