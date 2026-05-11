"""insider test-suite."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from insider import (
    ActivityCorpus,
    BENIGN_PROFILES,
    DetectorConfig,
    EventType,
    InsiderPipeline,
    InsiderThreatDetector,
    INSIDER_SCENARIOS,
    LLMInsiderAnalyst,
    SyntheticActivityGenerator,
    UserActivity,
    UserEvent,
    UserFeatureExtractor,
    extract_user_day_features,
    parse_activity_jsonl,
    parse_activity_lines,
)
from insider.analyst import _coerce_report, KNOWN_ARCHETYPES
from insider.features import FEATURE_NAMES

FIXTURE_DIR = Path(_HERE).parent / "fixtures"


# ---- events --------------------------------------------------------------


def _ev(ts="2025-01-13T10:00:00+00:00", uid="alice",
        et=EventType.LOGIN, **attrs):
    return UserEvent(
        timestamp=datetime.fromisoformat(ts),
        user_id=uid, event_type=et, attrs=dict(attrs),
    )


def test_user_event_hour_and_date_key():
    e = _ev("2025-01-13T14:32:11+00:00")
    assert e.hour == 14
    assert e.date_key == "2025-01-13"


def test_user_event_to_dict_round_trips_basic_fields():
    e = _ev(et=EventType.FILE_ACCESS, path="/x", op="read", bytes=10)
    d = e.to_dict()
    assert d["event_type"] == "file_access"
    assert d["attrs"]["path"] == "/x"


def test_user_activity_rejects_wrong_user():
    a = UserActivity(user_id="alice", date_key="2025-01-13")
    with pytest.raises(ValueError):
        a.add(_ev(uid="bob"))


def test_user_activity_rejects_wrong_date():
    a = UserActivity(user_id="alice", date_key="2025-01-12")
    with pytest.raises(ValueError):
        a.add(_ev())


def test_activity_corpus_by_user_groups():
    c = ActivityCorpus()
    c.add(UserActivity(user_id="alice", date_key="2025-01-13"))
    c.add(UserActivity(user_id="alice", date_key="2025-01-14"))
    c.add(UserActivity(user_id="bob", date_key="2025-01-13"))
    by = c.by_user()
    assert sorted(by) == ["alice", "bob"]
    assert len(by["alice"]) == 2


# ---- synth ---------------------------------------------------------------


def test_baseline_has_expected_event_types():
    gen = SyntheticActivityGenerator(seed=1)
    acts = gen.generate_baseline(n_days=1, n_per_profile_per_day=1)
    assert len(acts) == len(BENIGN_PROFILES)
    types = {e.event_type for a in acts for e in a.events}
    assert EventType.LOGIN in types
    assert EventType.FILE_ACCESS in types


def test_baseline_labels_are_benign():
    gen = SyntheticActivityGenerator(seed=1)
    acts = gen.generate_baseline(n_days=1)
    assert all(a.label == "benign" for a in acts)


def test_insider_day_data_hoarder_has_sensitive_paths_spike():
    gen = SyntheticActivityGenerator(seed=2)
    a = gen.generate_insider_day("fin_carol", "data_hoarder", seed=2)
    assert a.label == "insider:data_hoarder"
    sensitive = sum(
        1 for e in a.events
        if e.event_type == EventType.FILE_ACCESS
        and "_pii" in str(e.attrs.get("path", "")).lower()
    )
    assert sensitive > 30


def test_insider_day_exfil_email_attaches_dlp_alert():
    gen = SyntheticActivityGenerator(seed=2)
    a = gen.generate_insider_day("sales_bob", "exfil_email", seed=2)
    assert any(e.event_type == EventType.DLP_ALERT for e in a.events)


def test_insider_day_unknown_user_raises():
    gen = SyntheticActivityGenerator(seed=2)
    with pytest.raises(KeyError):
        gen.generate_insider_day("nobody", "data_hoarder")


def test_insider_day_unknown_scenario_raises():
    gen = SyntheticActivityGenerator(seed=2)
    with pytest.raises(KeyError):
        gen.generate_insider_day("dev_alice", "no_such_scenario")


def test_all_scenarios_label_correctly():
    gen = SyntheticActivityGenerator(seed=2)
    for s in INSIDER_SCENARIOS:
        a = gen.generate_insider_day("dev_alice", s.name, seed=3)
        assert a.label == f"insider:{s.name}"


# ---- parser --------------------------------------------------------------


def test_parser_skips_blank_and_comments():
    lines = [
        "",
        "# comment",
        '{"ts": "2025-01-13T09:00:00+00:00", "user_id": "x", "event_type": "login"}',
    ]
    acts = parse_activity_lines(lines)
    assert len(acts) == 1
    assert acts[0].user_id == "x"


def test_parser_skips_invalid_json_and_unknown_event_type():
    lines = [
        "not json",
        '{"ts": "2025-01-13T09:00:00+00:00", "user_id": "x", "event_type": "fly_to_moon"}',
        '{"ts": "2025-01-13T09:00:00+00:00", "user_id": "x", "event_type": "login"}',
    ]
    acts = parse_activity_lines(lines)
    assert len(acts) == 1


def test_parser_groups_by_user_and_day():
    lines = [
        '{"ts": "2025-01-13T09:00:00+00:00", "user_id": "x", "event_type": "login"}',
        '{"ts": "2025-01-13T10:00:00+00:00", "user_id": "x", "event_type": "login"}',
        '{"ts": "2025-01-14T09:00:00+00:00", "user_id": "x", "event_type": "login"}',
        '{"ts": "2025-01-13T09:00:00+00:00", "user_id": "y", "event_type": "login"}',
    ]
    acts = parse_activity_lines(lines)
    assert len(acts) == 3  # x-13, x-14, y-13


def test_parser_handles_z_suffix_timestamp():
    lines = ['{"ts": "2025-01-13T09:00:00Z", "user_id": "x", "event_type": "login"}']
    [a] = parse_activity_lines(lines)
    assert a.events[0].timestamp.tzinfo is not None


def test_parser_loads_real_fixture():
    acts = parse_activity_jsonl(str(FIXTURE_DIR / "sample_week.jsonl"))
    users = {a.user_id for a in acts}
    assert {"fin_carol", "sales_bob", "dev_alice"}.issubset(users)


def test_parser_skips_event_missing_required_fields():
    lines = [
        '{"ts": "2025-01-13T09:00:00+00:00", "event_type": "login"}',  # no user_id
        '{"ts": "2025-01-13T09:00:00+00:00", "user_id": "x", "event_type": "login"}',
    ]
    acts = parse_activity_lines(lines)
    assert len(acts) == 1


# ---- features ------------------------------------------------------------


def test_feature_names_unique_and_nonempty():
    assert len(FEATURE_NAMES) > 0
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_extract_features_for_empty_activity_returns_zero_vector():
    a = UserActivity(user_id="x", date_key="2025-01-13")
    v = extract_user_day_features(a)
    assert v.shape == (len(FEATURE_NAMES),)
    assert (v == 0).all() or v.sum() == 0


def test_extract_features_counts_logins():
    a = UserActivity(user_id="x", date_key="2025-01-13")
    a.add(_ev("2025-01-13T09:00:00+00:00", "x", EventType.LOGIN, success=True))
    a.add(_ev("2025-01-13T10:00:00+00:00", "x", EventType.LOGIN, success=False))
    v = extract_user_day_features(a)
    idx_l = FEATURE_NAMES.index("vol_login_count")
    idx_f = FEATURE_NAMES.index("vol_login_failed")
    assert v[idx_l] == 2
    assert v[idx_f] == 1


def test_extract_features_marks_off_hours():
    a = UserActivity(user_id="x", date_key="2025-01-13")
    a.add(_ev("2025-01-13T03:00:00+00:00", "x", EventType.LOGIN))
    a.add(_ev("2025-01-13T22:00:00+00:00", "x", EventType.LOGIN))
    v = extract_user_day_features(a)
    idx = FEATURE_NAMES.index("temp_off_hours_frac")
    assert v[idx] == 1.0
    assert v[FEATURE_NAMES.index("temp_late_night_events")] == 1


def test_extract_features_picks_up_sensitive_paths():
    a = UserActivity(user_id="x", date_key="2025-01-13")
    a.add(_ev("2025-01-13T10:00:00+00:00", "x", EventType.FILE_ACCESS,
              path="/finance/payroll/q1.csv", op="read", bytes=10))
    v = extract_user_day_features(a)
    assert v[FEATURE_NAMES.index("file_sensitive_hits")] >= 1


def test_extract_features_picks_up_personal_email():
    a = UserActivity(user_id="alice", date_key="2025-01-13")
    a.add(_ev("2025-01-13T10:00:00+00:00", "alice", EventType.EMAIL_SEND,
              to="alice@gmail.example", size_bytes=1000, attachment_count=1))
    v = extract_user_day_features(a)
    assert v[FEATURE_NAMES.index("comms_personal_domain_frac")] == 1.0
    assert v[FEATURE_NAMES.index("exfil_personal_self_email")] == 1


def test_extract_features_picks_up_cloud_storage_hits():
    a = UserActivity(user_id="x", date_key="2025-01-13")
    a.add(_ev("2025-01-13T10:00:00+00:00", "x", EventType.WEB,
              host="dropbox.example", bytes=1000))
    v = extract_user_day_features(a)
    assert v[FEATURE_NAMES.index("exfil_cloud_host_hits")] == 1


def test_user_feature_extractor_transform_stacks():
    fx = UserFeatureExtractor()
    gen = SyntheticActivityGenerator(seed=5)
    acts = gen.generate_baseline(n_days=2)
    arr = fx.transform(acts)
    assert arr.shape == (len(acts), len(FEATURE_NAMES))


def test_user_feature_extractor_empty_returns_2d():
    fx = UserFeatureExtractor()
    arr = fx.transform([])
    assert arr.shape == (0, len(FEATURE_NAMES))


# ---- detector ------------------------------------------------------------


def _train_default(seed=1):
    gen = SyntheticActivityGenerator(seed=seed)
    base = gen.generate_baseline(n_days=14)
    return InsiderThreatDetector(DetectorConfig(random_state=seed)).fit(base)


def test_detector_fit_requires_nonempty():
    with pytest.raises(ValueError):
        InsiderThreatDetector().fit([])


def test_detector_predict_before_fit_raises():
    with pytest.raises(RuntimeError):
        InsiderThreatDetector().predict([])


def test_detector_per_role_fit_creates_role_models():
    det = _train_default()
    assert "developer" in det._models or "_global" in det._models


def test_detector_baseline_user_scores_below_insider():
    det = _train_default(seed=7)
    gen = SyntheticActivityGenerator(seed=7)
    benign_day = gen.generate_baseline(n_days=1)[0]
    insider_day = gen.generate_insider_day("fin_carol", "data_hoarder", seed=7)
    [vb] = det.predict([benign_day])
    [vi] = det.predict([insider_day])
    assert vi.score > vb.score


def test_detector_flags_majority_of_insider_archetypes():
    """End-to-end: with a richer baseline + tuned threshold, the detector
    should score insider days higher than benign and flag the majority."""
    gen = SyntheticActivityGenerator(seed=11)
    base = gen.generate_baseline(n_days=30)
    cfg = DetectorConfig(random_state=11, suspicious_threshold=0.45)
    det = InsiderThreatDetector(cfg).fit(base)
    insiders = []
    users = ["dev_alice", "fin_carol", "sales_bob", "exec_eve",
             "adm_dave", "fin_carol"]
    scenarios = ["data_hoarder", "off_hours", "exfil_email",
                 "departing_employee", "privilege_escalator", "pii_browser"]
    for u, s in zip(users, scenarios):
        insiders.append(gen.generate_insider_day(u, s, seed=hash((u, s)) & 0xffff))
    verdicts = det.predict(insiders)
    n_susp = sum(1 for v in verdicts if v.suspicious)
    # Compare insider scores to a baseline mean to confirm the model
    # is at least *ordering* them correctly even if the absolute threshold
    # is conservative.
    benign_v = det.predict(base[:30])
    benign_mean = sum(v.score for v in benign_v) / len(benign_v)
    insider_mean = sum(v.score for v in verdicts) / len(verdicts)
    assert insider_mean > benign_mean, (insider_mean, benign_mean)
    assert n_susp >= 3, [(u, v.score) for u, v in zip(users, verdicts)]


def test_detector_save_and_load_roundtrip(tmp_path):
    det = _train_default(seed=2)
    p = tmp_path / "m.joblib"
    det.save(str(p))
    det2 = InsiderThreatDetector.load(str(p))
    gen = SyntheticActivityGenerator(seed=2)
    a = gen.generate_insider_day("fin_carol", "data_hoarder", seed=2)
    [v1] = det.predict([a])
    [v2] = det2.predict([a])
    assert abs(v1.score - v2.score) < 1e-9


def test_detector_load_rejects_unknown_schema(tmp_path):
    det = _train_default(seed=3)
    p = tmp_path / "m.joblib"
    det.save(str(p))
    import joblib
    payload = joblib.load(p)
    payload["schema_version"] = 999
    joblib.dump(payload, p)
    with pytest.raises(ValueError):
        InsiderThreatDetector.load(str(p))


def test_detector_verdict_top_features_nonempty():
    det = _train_default(seed=4)
    gen = SyntheticActivityGenerator(seed=4)
    a = gen.generate_insider_day("fin_carol", "data_hoarder", seed=4)
    [v] = det.predict([a])
    assert len(v.top_features) > 0


# ---- analyst -------------------------------------------------------------


def test_coerce_report_clamps_severity_and_archetype():
    raw = json.dumps({
        "headline": "x", "archetype": "definitely_not_an_archetype",
        "severity": "DOOM", "summary": "s", "confidence": 0.5,
        "affected_users": [], "indicators": [], "recommended_actions": [],
    })
    rep = _coerce_report(raw, [])
    assert rep.archetype == "unknown"
    assert rep.severity == "medium"


def test_coerce_report_clamps_confidence():
    raw = json.dumps({
        "headline": "x", "archetype": "data_hoarder", "severity": "high",
        "summary": "s", "confidence": -7.0,
        "affected_users": [], "indicators": [], "recommended_actions": [],
    })
    assert _coerce_report(raw, []).confidence == 0.0
    raw = json.dumps({
        "headline": "x", "archetype": "data_hoarder", "severity": "high",
        "summary": "s", "confidence": 99.0,
        "affected_users": [], "indicators": [], "recommended_actions": [],
    })
    assert _coerce_report(raw, []).confidence == 1.0


def test_coerce_report_drops_invented_users():
    from insider.detector import UserVerdict as V
    real = V(user_id="alice", date_key="2025-01-13", role="dev",
             score=0.9, suspicious=True)
    raw = json.dumps({
        "headline": "x", "archetype": "data_hoarder", "severity": "high",
        "summary": "s", "confidence": 0.5,
        "affected_users": [
            {"user_id": "alice", "date_key": "2025-01-13", "rationale": "ok"},
            {"user_id": "ghost", "date_key": "2025-01-13", "rationale": "fake"},
        ],
        "indicators": [], "recommended_actions": [],
    })
    rep = _coerce_report(raw, [real])
    assert len(rep.affected_users) == 1
    assert rep.affected_users[0]["user_id"] == "alice"


def test_coerce_report_handles_garbled():
    rep = _coerce_report("totally not json", [])
    assert rep.fallback is True


def test_coerce_report_handles_codefence():
    payload = {
        "headline": "x", "archetype": "data_hoarder", "severity": "high",
        "summary": "s", "confidence": 0.5,
        "affected_users": [], "indicators": ["i1"], "recommended_actions": ["a1"],
    }
    raw = "Sure:\n```json\n" + json.dumps(payload) + "\n```\n"
    rep = _coerce_report(raw, [])
    assert rep.fallback is False
    assert rep.indicators == ["i1"]


def test_known_archetypes_set_includes_unknown():
    assert "unknown" in KNOWN_ARCHETYPES


def test_analyst_with_no_client_returns_heuristic():
    from insider.detector import UserVerdict as V
    a = LLMInsiderAnalyst(client=None)
    v = V(user_id="x", date_key="2025-01-13", role="dev", score=0.8, suspicious=True)
    rep = a.analyse([v], [])
    assert rep.fallback is True


def test_analyst_with_no_verdicts_returns_clean():
    a = LLMInsiderAnalyst(client=None)
    rep = a.analyse([], [])
    assert rep.severity == "low"
    assert rep.fallback is False


# ---- pipeline ------------------------------------------------------------


class _FakeLLM:
    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    def chat(self, *args, **kwargs):
        self.calls += 1
        content = self._payload if isinstance(self._payload, str) else json.dumps(self._payload)
        return types.SimpleNamespace(content=content)


def test_pipeline_end_to_end_with_fake_llm():
    det = _train_default(seed=8)
    fake = _FakeLLM({
        "headline": "Bulk personal-email exfil",
        "archetype": "exfil_via_email",
        "severity": "high",
        "summary": "Sales user sent many emails to personal domains in one day with DLP hit.",
        "confidence": 0.85,
        "affected_users": [],  # filled at coerce; verdicts will be matched
        "indicators": ["DLP rule EMAIL_BULK_TO_PERSONAL fired"],
        "recommended_actions": ["Disable user's email send", "Engage HR"],
    })
    analyst = LLMInsiderAnalyst(client=fake)
    pipeline = InsiderPipeline(detector=det, analyst=analyst, enable_llm=True)
    acts = parse_activity_jsonl(str(FIXTURE_DIR / "sample_week.jsonl"))
    result = pipeline.run(acts)
    assert any(v.suspicious for v in result.verdicts)
    assert result.report is not None
    assert fake.calls == 1
    assert result.report.archetype == "exfil_via_email"


def test_pipeline_no_suspicious_skips_llm():
    det = _train_default(seed=9)
    fake = _FakeLLM("never called")
    analyst = LLMInsiderAnalyst(client=fake)
    pipeline = InsiderPipeline(detector=det, analyst=analyst, enable_llm=True)
    gen = SyntheticActivityGenerator(seed=9)
    benign = gen.generate_baseline(n_days=1)
    result = pipeline.run(benign)
    # Some baseline days might still pass the threshold; only assert about LLM call
    if not any(v.suspicious for v in result.verdicts):
        assert fake.calls == 0
        assert result.report is not None
        assert result.report.severity == "low"


def test_pipeline_disabled_llm_returns_no_report():
    det = _train_default(seed=10)
    pipeline = InsiderPipeline(detector=det, analyst=None, enable_llm=False)
    acts = parse_activity_jsonl(str(FIXTURE_DIR / "sample_week.jsonl"))
    result = pipeline.run(acts)
    assert result.report is None


def test_pipeline_to_dict_is_json_serialisable():
    det = _train_default(seed=11)
    pipeline = InsiderPipeline(detector=det, analyst=None, enable_llm=False)
    acts = parse_activity_jsonl(str(FIXTURE_DIR / "sample_week.jsonl"))
    result = pipeline.run(acts)
    blob = json.dumps(result.to_dict(), default=str)
    assert "verdicts" in blob


# ---- LLM live ------------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("LLM_LIVE") != "1",
    reason="set LLM_LIVE=1 to run live LLM smoke",
)
def test_llm_live_full_pipeline_with_real_llm():
    det = _train_default(seed=42)
    analyst = LLMInsiderAnalyst()
    pipeline = InsiderPipeline(detector=det, analyst=analyst, enable_llm=True)
    acts = parse_activity_jsonl(str(FIXTURE_DIR / "sample_week.jsonl"))
    result = pipeline.run(acts)
    assert result.report is not None
    print(f"\nlive insider report:")
    print(f"  headline:   {result.report.headline}")
    print(f"  archetype:  {result.report.archetype}")
    print(f"  severity:   {result.report.severity}")
    print(f"  confidence: {result.report.confidence}")
    print(f"  affected:   {len(result.report.affected_users)}")
    print(f"  actions:    {len(result.report.recommended_actions)}")
    assert result.report.severity in {"low", "medium", "high", "critical"}
    assert result.report.archetype in KNOWN_ARCHETYPES
    assert 0.0 <= result.report.confidence <= 1.0
    valid_keys = {(v.user_id, v.date_key) for v in result.verdicts if v.suspicious}
    for u in result.report.affected_users:
        assert (u["user_id"], u["date_key"]) in valid_keys
