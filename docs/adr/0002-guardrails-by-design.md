# 2. The ethical guardrails are the architecture, not a policy bolt-on

Date: 2026-08-24
Status: Accepted

## Context
A behavioural insider-risk tool can harm people: a false positive is a suspicion
against a named colleague. If restraint is left to "how the org uses it", the
tool's defaults will hurt someone.

## Decision
Bake restraint into the engine:
- `Assessment` always includes an `explanation`; there is no code path that emits a
  score without one.
- `review_required` is a property of an elevated assessment — the type system nudges
  every consumer toward human review, and there is no method that takes adverse
  action.
- Warm-up is enforced in the baseline: below it, the status is
  `insufficient-baseline` and the score is 0, so a new employee is never scored
  against noise.
- Peer-group discounting contextualises individual deviation.

## Consequences
- Misuse (auto-disabling accounts on a score) requires building something this
  library deliberately does not provide.
- The explanation requirement is tested (`test_explanation_never_empty`), as is the
  warm-up guard.
- Cost: the tool cannot "just give a number" for automation. That is intentional.
