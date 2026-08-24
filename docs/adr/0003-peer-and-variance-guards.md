# 3. Guard against team-of-one and zero-variance degeneracies

Date: 2026-08-24
Status: Accepted

## Context
Two degenerate cases produce badly wrong signals, both found while building:
1. A user who is the only member of their peer group: the group baseline is their
   own data, so peer discounting cancels every signal (a real anomaly scored 0).
2. A user with a perfectly constant baseline: dividing by a zero std is undefined;
   an early version fabricated a 3σ score from any change, auto-elevating on noise.

## Decision
- Peer discounting applies only when the group has >= 2 distinct members; otherwise
  no discounting (peer_z = 0).
- A zero-variance metric returns a modest fixed signal (1.0) on change — visible in
  the contributions, but never alone enough to elevate.

## Consequences
- A solo user's genuine anomaly is caught (`test`: score high, elevated) instead of
  being cancelled by self-comparison.
- A tiny change from a rock-steady baseline is noted but does not fabricate an
  alarm (`test_zero_variance_change_is_not_alone_elevating`).
- Both guards are documented and tested so a future refactor cannot silently
  reintroduce the degeneracy.
