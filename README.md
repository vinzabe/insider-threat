# insider-threat

Behavioural **insider-risk detector** with an LLM narrative analyst
that maps anomalies to known insider archetypes (data hoarder,
departing employee, off-hours actor, privilege escalator,
exfil-by-email, exfil-by-cloud-storage, compromised account, policy
violator) -- with hallucination guards that drop any user the LLM
invents.

```
JSONL activity log
   -> parser              UserActivity per (user_id, day)
   -> features            27-dim per-user-day vector
   -> InsiderThreatDetector  per-role IsolationForest, anomaly score in [0,1]
   -> LLMInsiderAnalyst   incident report mapped to a known archetype
```

## Why per-role IsolationForest?

Insider behaviour is *distributionally weird relative to the user's own
baseline*, not "labelled malicious".  A finance user reading
`/finance/q1.csv` is benign; a developer reading the same file at
03:00 is not.  Per-role IForest lets the model carry that context
cheaply and without hand-tuned thresholds per signal.

The supervised path (gradient-boosted classifier over labelled data)
is exposed for operators who do have labelled data, but the default
is unsupervised so the system works on day one.

## Hallucination guards

* `archetype` -- must be one of the 9 known labels; otherwise dropped to `unknown`
* `severity` -- clamped to `low|medium|high|critical`
* `confidence` -- clamped to `[0, 1]`
* `affected_users[*]` -- must reference a `(user_id, date_key)` from the input verdicts
* `recommended_actions` capped at 8 entries, `indicators` at 8

## Quick start

```bash
pip install -r requirements.txt

# 1. Train per-role baseline
python -m insider.cli train --out detector.joblib --days 21

# 2. Score a JSONL activity log
python -m insider.cli scan --model detector.joblib \
    --input fixtures/sample_week.jsonl --llm
```

## Bundled scenarios

| archetype              | overlay                                                   |
|------------------------|-----------------------------------------------------------|
| data_hoarder           | spike in sensitive file-access count                      |
| off_hours              | activity in 01-05 on a 9-to-5 user                        |
| departing_employee     | USB write surge + bulk personal-domain self-email         |
| privilege_escalator    | many failed logins to admin hosts                         |
| exfil_email            | bulk personal-domain email + DLP alert                    |
| pii_browser            | many large posts to personal cloud-storage hosts          |

Sample LLM live output on `fixtures/sample_week.jsonl` (which contains
fin_carol/data_hoarder + sales_bob/exfil_email + dev_alice/departing_employee):

```
headline:   Dual-user data exfiltration via email and USB
archetype:  exfil_via_email
severity:   high
confidence: 0.88
affected:   2
actions:    7
```

All affected users are present in the input verdicts; none were invented.

## Library use

```python
from insider import (
    SyntheticActivityGenerator, InsiderThreatDetector, DetectorConfig,
    LLMInsiderAnalyst, InsiderPipeline, parse_activity_jsonl,
)

gen = SyntheticActivityGenerator(seed=1)
det = InsiderThreatDetector(DetectorConfig()).fit(gen.generate_baseline(n_days=21))
pipeline = InsiderPipeline(detector=det, analyst=LLMInsiderAnalyst())

acts = parse_activity_jsonl("fixtures/sample_week.jsonl")
result = pipeline.run(acts)
print(result.report.archetype, result.report.severity)
```

## Layout

```
insider/
  events.py     EventType, UserEvent, UserActivity, ActivityCorpus
  synth.py      5 user profiles + 6 insider-overlay scenarios
  parser.py     JSONL activity log -> UserActivity
  features.py   FEATURE_NAMES (27), UserFeatureExtractor
  detector.py   InsiderThreatDetector (per-role IForest) + persistence
  analyst.py    LLMInsiderAnalyst + InsiderIncidentReport (validated)
  pipeline.py   InsiderPipeline + PipelineResult
  cli.py        insider {train, scan}
fixtures/
  sample_week.jsonl   2 baseline days + 3 insider scenarios
tests/
  test_insider.py     47 unit + 1 LLM_LIVE smoke
```

## Tests

```bash
pytest tests/ -v
LLM_LIVE=1 pytest tests/ -v
```

47 unit tests cover parser robustness, feature schema stability,
detector training/persistence/threshold behaviour, and analyst
hallucination guards.  1 LLM_LIVE smoke validates that every affected
user cited in the LLM report is present in the input verdicts.

## License

MIT
