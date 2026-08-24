"""insider — behavioural baselining for insider-risk, built with guardrails.

This category is ethically loaded: a false positive is a formal suspicion against a
colleague. That is a design constraint, not an afterthought. So this engine bakes
in restraint:

  * A deviation is never surfaced without a **human-readable explanation** of which
    behaviours drove it and by how much.
  * Baselines have an explicit **warm-up**; a user with too little history is
    reported as 'insufficient-baseline', never scored against noise.
  * Peer-group comparison contextualises deviation (a spike everyone on the team
    shows is not an individual anomaly).
  * The output is **review-required** by construction — there is no automated
    adverse-action path, and the API/docs say so.
"""
__version__ = "1.0.0"
