# Threat model, scope & ethics

## What this is
A behavioural baselining engine that flags statistically unusual activity for
**human review**, with explanations and guardrails designed in. It is a triage aid
for a trained analyst, not a verdict machine.

## Ethical stance (non-negotiable in this design)
- **Output is review-required, never an action.** No method disables accounts,
  notifies HR, or takes any adverse action. Building that is out of scope by intent.
- **Every flag is explained.** An analyst sees which behaviours drove a score.
- **New/low-history users are not scored.** Warm-up prevents judging against noise.
- **Retention/consent are the deployer's legal duty.** This engine keeps only
  running statistics (mean/variance), not raw activity history — minimising what is
  stored — but lawful basis, notice, and retention policy are the operator's.

## Trust boundaries & limits
- **Inputs are trusted, pre-aggregated features** (counts/rates per user per
  period). Feature engineering and PII minimisation happen upstream; garbage or
  biased features produce garbage or biased scores.
- **Statistical, not causal.** A high score means "unusual for this person vs their
  peers", not "malicious". Many benign events (a new project, a role change) look
  anomalous; that is exactly why it is review-required.
- **Gameable.** An insider who changes behaviour slowly stays within a drifting
  baseline. This raises the bar; it is not a guarantee.
- **Fairness.** Peer groups must be constructed carefully; a badly-chosen group can
  encode bias. The engine contextualises against the group it is given — choosing
  fair groups is the operator's responsibility, and a documented risk.

## Non-goals
- Automated response of any kind.
- Attribution of intent.
- A substitute for due process.

## Reporting
A scoring path that could emit an elevation without an explanation, or bypass
warm-up, is treated as a serious bug — report to **gabejar@usa.com**.
