r"""LLM-backed insider-threat narrative analyst.

For each suspicious user-day, build a compact evidence summary, ask the
LLM for an incident report mapping the behaviour to one of the known
insider-risk archetypes, and validate the JSON response.

Hallucination guards:

* ``user_id`` in ``affected_users`` must match an input verdict
* ``archetype`` must be one of the known archetype labels
* ``severity`` clamped to ``low|medium|high|critical``
* ``confidence`` clamped to ``[0, 1]``
* ``recommended_actions`` capped at 8
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .detector import UserVerdict
from .events import EventType, UserActivity

try:
    from .llm_client import LLMClient
except Exception:  # pragma: no cover
    LLMClient = None  # type: ignore


KNOWN_ARCHETYPES = {
    "data_hoarder",
    "off_hours_actor",
    "departing_employee",
    "privilege_escalator",
    "exfil_via_email",
    "exfil_via_cloud_storage",
    "compromised_account",
    "policy_violator",
    "unknown",
}

_ALLOWED_SEV = {"low", "medium", "high", "critical"}


@dataclass
class InsiderIncidentReport:
    headline: str
    archetype: str
    severity: str
    summary: str
    affected_users: List[Dict[str, Any]] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_response: Optional[str] = None
    fallback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headline": self.headline,
            "archetype": self.archetype,
            "severity": self.severity,
            "summary": self.summary,
            "affected_users": list(self.affected_users),
            "indicators": list(self.indicators),
            "recommended_actions": list(self.recommended_actions),
            "confidence": self.confidence,
            "fallback": self.fallback,
        }


def _build_evidence(
    verdicts: Sequence[UserVerdict],
    activity_index: Dict[tuple, UserActivity],
    top_k: int,
) -> List[Dict[str, Any]]:
    sorted_v = sorted(verdicts, key=lambda v: v.score, reverse=True)[:top_k]
    out: List[Dict[str, Any]] = []
    for v in sorted_v:
        a = activity_index.get((v.user_id, v.date_key))
        sample_paths: List[str] = []
        sample_recipients: List[str] = []
        sample_hosts: List[str] = []
        usb_bytes = 0
        n_off_hours_login = 0
        n_dlp = 0
        if a is not None:
            for e in a.events:
                if e.event_type == EventType.FILE_ACCESS:
                    p = str(e.attrs.get("path", ""))
                    if p and p not in sample_paths:
                        sample_paths.append(p)
                if e.event_type == EventType.EMAIL_SEND:
                    r = str(e.attrs.get("to", ""))
                    if r and r not in sample_recipients:
                        sample_recipients.append(r)
                if e.event_type == EventType.WEB:
                    h = str(e.attrs.get("host", ""))
                    if h and h not in sample_hosts:
                        sample_hosts.append(h)
                if e.event_type == EventType.USB and e.attrs.get("op") == "write":
                    usb_bytes += int(e.attrs.get("bytes", 0))
                if e.event_type == EventType.LOGIN and (e.hour < 7 or e.hour >= 20):
                    n_off_hours_login += 1
                if e.event_type == EventType.DLP_ALERT:
                    n_dlp += 1
        out.append({
            "user_id": v.user_id,
            "date_key": v.date_key,
            "role": v.role,
            "score": round(v.score, 4),
            "top_features": [(n, round(s, 3)) for n, s in v.top_features],
            "sample_file_paths": sample_paths[:8],
            "sample_email_recipients": sample_recipients[:8],
            "sample_web_hosts": sample_hosts[:8],
            "usb_write_bytes": usb_bytes,
            "off_hours_logins": n_off_hours_login,
            "dlp_alerts": n_dlp,
        })
    return out


_SYSTEM_PROMPT = (
    "You are an enterprise insider-risk analyst. You receive a JSON list of "
    "users that an unsupervised behavioural model flagged as anomalous. "
    "Produce a JSON incident report that classifies the case into a known "
    "insider archetype. Only emit JSON, no preamble. Schema:\n"
    "{\n"
    '  "headline": str,\n'
    '  "archetype": "data_hoarder"|"off_hours_actor"|"departing_employee"'
    '|"privilege_escalator"|"exfil_via_email"|"exfil_via_cloud_storage"'
    '|"compromised_account"|"policy_violator"|"unknown",\n'
    '  "severity": "low"|"medium"|"high"|"critical",\n'
    '  "summary": str,    // 2-4 sentences\n'
    '  "affected_users": [{"user_id": str, "date_key": str, "rationale": str}],\n'
    '  "indicators": [str],          // <= 8 short indicators\n'
    '  "recommended_actions": [str], // <= 8 imperative actions\n'
    '  "confidence": float           // 0..1\n'
    "}\n"
    "Rules: only reference user_ids/date_keys that appear in the supplied "
    "evidence. Do not invent IPs, hashes, or hostnames. Keep total response "
    "under 1800 characters."
)


def _coerce_report(
    raw: str, verdicts: Sequence[UserVerdict]
) -> InsiderIncidentReport:
    valid_keys = {(v.user_id, v.date_key) for v in verdicts}
    try:
        if "```" in raw:
            blocks = re.findall(r"```(?:json)?\s*(.*?)```", raw, flags=re.DOTALL)
            raw_json = blocks[0] if blocks else raw
        else:
            raw_json = raw
        data = json.loads(raw_json.strip())
    except Exception:
        return InsiderIncidentReport(
            headline="Suspicious user activity detected",
            archetype="unknown",
            severity="medium",
            summary="LLM response could not be parsed; raw evidence retained.",
            affected_users=[
                {"user_id": v.user_id, "date_key": v.date_key,
                 "rationale": "Anomaly score above threshold"}
                for v in verdicts
            ],
            indicators=[],
            recommended_actions=[
                "Engage HR + security to interview user",
                "Suspend external transfer privileges pending review",
            ],
            confidence=0.3,
            raw_response=raw,
            fallback=True,
        )

    headline = str(data.get("headline", ""))[:180] or "Suspicious user activity"
    archetype = str(data.get("archetype", "unknown"))
    if archetype not in KNOWN_ARCHETYPES:
        archetype = "unknown"
    severity = str(data.get("severity", "medium")).lower()
    if severity not in _ALLOWED_SEV:
        severity = "medium"
    summary = str(data.get("summary", ""))[:1200]
    confidence = data.get("confidence", 0.5)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    aff_raw = data.get("affected_users", []) or []
    affected: List[Dict[str, Any]] = []
    for a in aff_raw[:16]:
        if not isinstance(a, dict):
            continue
        uid = str(a.get("user_id", ""))
        dk = str(a.get("date_key", ""))
        if (uid, dk) not in valid_keys:
            continue
        affected.append({
            "user_id": uid,
            "date_key": dk,
            "rationale": str(a.get("rationale", ""))[:240],
        })

    inds_raw = data.get("indicators", []) or []
    indicators = [str(s)[:200] for s in inds_raw if isinstance(s, (str, int, float))][:8]
    actions_raw = data.get("recommended_actions", []) or []
    actions = [str(s)[:240] for s in actions_raw if isinstance(s, (str, int, float))][:8]

    return InsiderIncidentReport(
        headline=headline,
        archetype=archetype,
        severity=severity,
        summary=summary,
        affected_users=affected,
        indicators=indicators,
        recommended_actions=actions,
        confidence=confidence,
        raw_response=raw,
        fallback=False,
    )


_AUTO = object()


@dataclass
class LLMInsiderAnalyst:
    client: Any = _AUTO
    model: str = os.environ.get("INSIDER_LLM_MODEL", "glm-5.1")
    temperature: float = 0.1
    max_tokens: int = 900
    top_k: int = 5

    def __post_init__(self) -> None:
        if self.client is _AUTO:
            if LLMClient is None:
                self.client = None
            else:
                try:
                    self.client = LLMClient()
                except Exception:
                    self.client = None

    def analyse(
        self,
        verdicts: Sequence[UserVerdict],
        activities: Sequence[UserActivity],
    ) -> InsiderIncidentReport:
        if not verdicts:
            return InsiderIncidentReport(
                headline="No suspicious users",
                archetype="unknown",
                severity="low",
                summary="Detector flagged nothing above threshold.",
                affected_users=[],
                indicators=[],
                recommended_actions=[],
                confidence=0.95,
                fallback=False,
            )
        if self.client is None:
            return InsiderIncidentReport(
                headline="ML detector flagged users (LLM offline)",
                archetype="unknown",
                severity="medium",
                summary="No LLM available; heuristic report only.",
                affected_users=[
                    {"user_id": v.user_id, "date_key": v.date_key,
                     "rationale": "Anomaly score above threshold"}
                    for v in sorted(verdicts, key=lambda x: x.score, reverse=True)[: self.top_k]
                ],
                indicators=[],
                recommended_actions=["Triage manually", "Pull full activity log"],
                confidence=0.4,
                fallback=True,
            )

        index = {(a.user_id, a.date_key): a for a in activities}
        evidence = _build_evidence(verdicts, index, self.top_k)
        user = (
            "Evidence (JSON):\n" + json.dumps(evidence, indent=2)
            + "\n\nReturn the JSON report described in the system prompt only."
        )
        try:
            resp = self.client.chat(
                [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ],
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            raw = resp.content if hasattr(resp, "content") else str(resp)
        except Exception as exc:
            return InsiderIncidentReport(
                headline="LLM unavailable",
                archetype="unknown",
                severity="medium",
                summary=f"LLM call failed: {exc!s}",
                affected_users=[
                    {"user_id": v.user_id, "date_key": v.date_key,
                     "rationale": "Anomaly score above threshold"}
                    for v in sorted(verdicts, key=lambda x: x.score, reverse=True)[: self.top_k]
                ],
                indicators=[],
                recommended_actions=["Triage manually"],
                confidence=0.3,
                fallback=True,
            )
        return _coerce_report(raw, verdicts)
