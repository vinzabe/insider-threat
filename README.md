# insider-threat

**A behavioural baseline engine for insider-risk — built so a false positive can't become an accusation.**

This category is ethically loaded in a way most anomaly detectors aren't: a false positive here is a formal suspicion against a colleague. That is treated as a **design constraint**, not a disclaimer. Every part of the engine is shaped by it:

- **Every deviation carries a human-readable explanation** of which behaviours drove it and by how much. No unexplained score ever surfaces.
- **Explicit warm-up.** A user with too little history is reported as `insufficient-baseline` and *never scored against noise*.
- **Peer-group context.** A spike the whole team shows is discounted — an individual isn't anomalous for doing what everyone did. (And a team of one is never peer-discounted into silence.)
- **Review-required by construction.** An elevated assessment routes to a human. There is no automated adverse-action path, and the API says so.

```
$ insider assess events.json
Insider-risk assessment (review-required; NOT an accusation):

  ⚠ REVIEW  bob  score=8.4
       elevated: downloads 8.4σ above normal; off_hours_logins 3.1σ above normal
  · scored  alice  score=1.2
       within normal range for this user and their peer group
  · insufficient-baseline  dana  score=0.0
       only 6/14 observations; not scored to avoid judging against noise
```

## How scoring works

Per-user running baselines (Welford's online mean/variance — O(1) per event, no unbounded history) produce a z-score per metric. Each is discounted by the peer group's z-score for the same metric (net deviation), and the aggregate is the root-sum-square — which emphasises the one metric that genuinely moved rather than summing many small drifts into a false alarm. Elevation threshold is 3.0.

Two guardrails that came directly from building it:

- **A team of one is never peer-discounted.** If a user is the only member of their group, the "peer" baseline is just their own data — discounting would cancel every signal. Peer context applies only with ≥2 members.
- **A zero-variance baseline never fabricates a big score.** A user with perfectly constant history who changes slightly gets a *modest* signal, not a fake 3σ — because with no variance there's no scale to judge deviation. A lone zero-variance metric can't alone cross the threshold.

## Quickstart (60 seconds)

```bash
git clone https://github.com/vinzabe/insider-threat && cd insider-threat
python -m pip install -e ".[dev]"

insider assess events.json --warmup 14
insider assess events.json --json
```

Event log is a JSON array of `{"user", "group", "features": {metric: value}}`. Exit codes: `0` none elevated, `2` elevated (review required), `1` error.

## Development

```bash
python -m pip install -e ".[dev]"
pytest --cov=insider      # 15 tests, ~97% coverage
mypy --strict src/insider # clean
ruff check src tests      # clean
```

## License

MIT © vinzabe
