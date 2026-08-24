"""The scoring engine: per-user deviation, contextualised by peer group, always
with an explanation and a warm-up guard.
"""
from __future__ import annotations

import dataclasses

from .baseline import Baseline


@dataclasses.dataclass(frozen=True, slots=True)
class Contribution:
    metric: str
    value: float
    user_z: float
    peer_z: float

    @property
    def net_z(self) -> float:
        """Deviation from the user's own baseline, discounted by how much the whole
        peer group also moved (a team-wide spike is not an individual anomaly)."""
        if self.user_z >= 0:
            return max(0.0, self.user_z - max(0.0, self.peer_z))
        return min(0.0, self.user_z - min(0.0, self.peer_z))


@dataclasses.dataclass(frozen=True, slots=True)
class Assessment:
    user: str
    status: str                 # "scored" | "insufficient-baseline"
    score: float                # aggregate deviation, 0 if not scored
    contributions: tuple[Contribution, ...]
    explanation: str

    @property
    def elevated(self) -> bool:
        return self.status == "scored" and self.score >= 3.0

    @property
    def review_required(self) -> bool:
        """By design: an elevated assessment ALWAYS routes to human review. There
        is no automated adverse action."""
        return self.elevated


@dataclasses.dataclass(slots=True)
class Engine:
    warmup: int = 14
    users: dict[str, Baseline] = dataclasses.field(default_factory=dict)
    peers: dict[str, Baseline] = dataclasses.field(default_factory=dict)
    user_group: dict[str, str] = dataclasses.field(default_factory=dict)
    group_members: dict[str, set[str]] = dataclasses.field(default_factory=dict)

    def observe(self, user: str, group: str, features: dict[str, float]) -> None:
        self.user_group[user] = group
        self.group_members.setdefault(group, set()).add(user)
        self.users.setdefault(user, Baseline(self.warmup)).observe(features)
        self.peers.setdefault(group, Baseline(self.warmup)).observe(features)

    def assess(self, user: str, features: dict[str, float]) -> Assessment:
        ub = self.users.get(user)
        if ub is None or not ub.ready:
            n = ub.observations if ub else 0
            return Assessment(
                user=user, status="insufficient-baseline", score=0.0,
                contributions=(),
                explanation=(f"only {n}/{self.warmup} observations; not scored "
                             "to avoid judging against noise"))
        group = self.user_group.get(user, "")
        pb = self.peers.get(group)
        user_z = ub.zscores(features)
        # Peer discounting requires a real peer group: with a team of one the
        # group baseline is just this user's own data, so discounting would
        # cancel every signal. Only contextualise against >= 2 members.
        multi_member = len(self.group_members.get(group, set())) >= 2
        peer_z = (pb.zscores(features)
                  if pb and pb.ready and multi_member else {})

        contribs = tuple(
            Contribution(metric=k, value=features[k], user_z=z,
                         peer_z=peer_z.get(k, 0.0))
            for k, z in sorted(user_z.items(), key=lambda kv: abs(kv[1]),
                               reverse=True))
        # aggregate: root-sum-square of net deviations (bounded, emphasises the
        # metric that moved most rather than summing many small drifts)
        score = round(sum(c.net_z ** 2 for c in contribs) ** 0.5, 3)
        return Assessment(
            user=user, status="scored", score=score, contributions=contribs,
            explanation=_explain(contribs, score))


def _explain(contribs: tuple[Contribution, ...], score: float) -> str:
    if not contribs or score < 3.0:
        return "within normal range for this user and their peer group"
    top = [c for c in contribs if abs(c.net_z) >= 1.5][:3]
    parts = []
    for c in top:
        direction = "above" if c.net_z > 0 else "below"
        peer_note = ""
        if abs(c.peer_z) >= 1.5 and (c.peer_z > 0) == (c.user_z > 0):
            peer_note = " (partly a team-wide shift)"
        parts.append(f"{c.metric} {abs(c.net_z):.1f}σ {direction} normal{peer_note}")
    return "elevated: " + "; ".join(parts)
