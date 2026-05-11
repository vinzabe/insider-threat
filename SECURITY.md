# Security Policy

## Threat model

`insider-threat` consumes user activity logs and produces verdicts +
narrative reports about employees.  This is a high-stakes use case:

* a false positive can damage someone's career,
* a false negative can hide an active exfiltration,
* the data itself (who-talked-to-whom-when) is sensitive PII.

The package is built around three principles:

1. **Score on behaviour, not on identity.**  No model in this repo
   learns to discriminate by `user_id`; identity only joins the
   feature path so per-role baselines can be selected.
2. **Validate everything the LLM claims.**  An LLM that invents a
   user_id can put a real person in an HR investigation; we hard-drop
   those.
3. **Operate on bounded evidence.**  The advisor sends only top-K
   verdicts plus capped sample lists; full activity logs never leave
   the host.

## In-package controls

### Parser

* Unknown event types raise once per record and the record is dropped;
  the rest of the stream continues.
* Missing-field records are dropped, not poisoned with defaults.
* Timestamps are parsed strictly; an invalid timestamp drops the
  record.  All datetimes are normalised to UTC.

### Feature extractor

* The schema is fixed (`FEATURE_NAMES`); the persisted detector
  refuses to load against a mismatched schema.
* No code in the feature path executes content from the log: paths,
  hostnames, and recipient addresses are read as strings.

### Detector

* `joblib` payload carries a `schema_version`; loading an unknown
  version raises `ValueError`.
* `InsiderThreatDetector` is unsupervised by default (IForest),
  reducing the chance that a labelled-data leak becomes a model
  bias.
* Per-role models prevent "developers always look anomalous to the
  finance baseline" false positives.

### LLM analyst

* The advisor sends top 5 verdicts with capped sample evidence
  (paths, recipients, hosts each capped at 8 entries).
* `_coerce_report` validates the JSON:
  * `archetype` -- must be one of the 9 known labels; otherwise
    coerced to `unknown`
  * `severity` -- clamped to `low|medium|high|critical`
  * `confidence` -- clamped to `[0, 1]`
  * `affected_users[*]` -- `(user_id, date_key)` must appear in the
    input verdicts; otherwise dropped
  * `recommended_actions` capped at 8, `indicators` capped at 8
* On JSON parse failure or LLM transport error the analyst returns a
  deterministic heuristic report with `fallback=True`.

## Operator responsibilities

1. **Privacy & legal review before production.**  Workforce monitoring
   has employment-law and works-council implications in many
   jurisdictions.  Get counsel.
2. **Treat the LLM report as a triage hint, not ground truth.**
   Validators block invented users but cannot detect a *plausibly
   wrong* archetype assignment.  Always corroborate the underlying
   activity log before HR action.
3. **Minimise data flow to the LLM.**  Prefer a self-hosted endpoint
   and confirm your LLM provider does not train on the sent
   evidence.
4. **Bound retention.**  Activity logs are PII.  Do not retain them
   longer than your policy requires; the package supports streaming
   ingestion via `parser.parse_activity_lines`.
5. **Per-role baselines must include enough data.**  IForest needs
   at least a few hundred user-days per role for stable scoring;
   we recommend >= 21 days * 5 users per role before deployment.

## Threats NOT mitigated

* **Mimicry.**  An attacker who shapes their behaviour to look
  statistically benign will reduce recall.  This is one signal in a
  defence-in-depth stack, not a perimeter.
* **Account takeover.**  Genuine compromised-credential cases will
  look like the legitimate user's anomalies.  The analyst has a
  `compromised_account` archetype but cannot prove the case from
  activity alone.
* **Aggregation attacks across users.**  The current model scores
  per-user-day independently; coordinated low-and-slow exfiltration
  across 50 users will not light any single user's score.

## Reporting a vulnerability

Email vinzabe@users.noreply.github.com with affected file/line, repro
steps, and suggested mitigation.  Do not file public issues for
vulnerabilities.

## Contact

Responsible disclosure: **g@abejar.net**
