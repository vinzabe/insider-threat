"""Behaviour: warm-up guard, explanations, peer-group discounting."""
from insider.engine import Engine


def _baseline_user(engine, user, group, n, features):
    for _ in range(n):
        engine.observe(user, group, features)


def test_insufficient_baseline_not_scored():
    e = Engine(warmup=14)
    e.observe("alice", "eng", {"downloads": 5})
    a = e.assess("alice", {"downloads": 500})
    assert a.status == "insufficient-baseline"
    assert not a.elevated
    assert "not scored" in a.explanation


def test_normal_behaviour_not_elevated():
    e = Engine(warmup=10)
    import random
    rng = random.Random(3)
    for _ in range(30):
        e.observe("alice", "eng", {"downloads": 5 + rng.random()})
    a = e.assess("alice", {"downloads": 6.0})   # within normal spread
    assert not a.elevated
    assert "normal range" in a.explanation


def test_zero_variance_change_is_not_alone_elevating():
    """A change from a perfectly constant baseline is notable but must not, on its
    own, fabricate an elevation from a z-score we cannot actually compute."""
    e = Engine(warmup=10)
    _baseline_user(e, "alice", "eng", 20, {"downloads": 5.0})  # constant
    a = e.assess("alice", {"downloads": 6.0})
    assert not a.elevated   # modest signal, below threshold


def test_clear_anomaly_is_elevated_with_explanation():
    e = Engine(warmup=10)
    # alice normally downloads ~5 with small variation
    import random
    rng = random.Random(0)
    for _ in range(30):
        e.observe("alice", "eng", {"downloads": 5 + rng.random()})
    a = e.assess("alice", {"downloads": 200.0})
    assert a.elevated
    assert a.review_required
    assert "downloads" in a.explanation
    assert "above normal" in a.explanation


def test_team_wide_shift_is_discounted():
    """If the WHOLE team spikes, an individual is less anomalous."""
    e = Engine(warmup=5)
    import random
    rng = random.Random(1)
    # establish baselines for a team
    for _ in range(30):
        for u in ("alice", "bob", "carol"):
            e.observe(u, "eng", {"vpn_hours": 8 + rng.random()})
    # now everyone works a long day (team-wide shift), then assess alice
    for u in ("bob", "carol"):
        for _ in range(10):
            e.observe(u, "eng", {"vpn_hours": 16.0})
    solo = e.assess("alice", {"vpn_hours": 16.0})
    # alice's own z is high, but peer z is also high -> net discounted
    top = solo.contributions[0]
    assert top.net_z < top.user_z    # peer shift reduced the individual signal


def test_explanation_never_empty():
    e = Engine(warmup=5)
    for _ in range(10):
        e.observe("x", "g", {"a": 1.0})
    a = e.assess("x", {"a": 1.0})
    assert a.explanation
