from insider.baseline import Baseline, RunningStat


def test_running_stat_matches_known_values():
    s = RunningStat()
    for x in [2, 4, 4, 4, 5, 5, 7, 9]:
        s.update(x)
    assert abs(s.mean - 5.0) < 1e-9
    assert abs(s.std - 2.138) < 0.01   # sample std


def test_zscore_zero_at_mean():
    s = RunningStat()
    for x in [10, 10, 10, 10]:
        s.update(x)
    assert s.zscore(10) == 0.0


def test_warmup_gate():
    b = Baseline(warmup=5)
    for _ in range(4):
        b.observe({"logins": 3})
    assert not b.ready
    b.observe({"logins": 3})
    assert b.ready


def test_zscores_only_for_known_metrics():
    b = Baseline(warmup=1)
    b.observe({"a": 1.0})
    z = b.zscores({"a": 2.0, "unknown": 5.0})
    assert "a" in z and "unknown" not in z
