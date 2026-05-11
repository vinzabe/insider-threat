"""insider -- Behavioural insider-threat detector.

Per-user anomaly scoring over normalised activity events (logins, file
access, email, USB, web, DLP alerts) with an LLM narrative analyst
that maps the anomaly to risk archetypes (data hoarder, departing
employee, off-hours sweep, privilege escalator, exfil-by-email).

The package consumes JSONL activity logs in a stable schema; live
collectors are the operator's job, and we ship a synthetic generator
plus fixtures so the pipeline can be exercised end-to-end.
"""

from .events import EventType, UserEvent, UserActivity, ActivityCorpus
from .synth import (
    BENIGN_PROFILES,
    INSIDER_SCENARIOS,
    SyntheticActivityGenerator,
    UserProfile,
    InsiderScenario,
)
from .parser import parse_activity_jsonl, parse_activity_lines
from .features import (
    FEATURE_NAMES,
    UserFeatureExtractor,
    extract_user_day_features,
)
from .detector import (
    InsiderThreatDetector,
    DetectorConfig,
    UserVerdict,
)
from .analyst import (
    LLMInsiderAnalyst,
    InsiderIncidentReport,
)
from .pipeline import InsiderPipeline, PipelineResult

__all__ = [
    "EventType",
    "UserEvent",
    "UserActivity",
    "ActivityCorpus",
    "BENIGN_PROFILES",
    "INSIDER_SCENARIOS",
    "SyntheticActivityGenerator",
    "UserProfile",
    "InsiderScenario",
    "parse_activity_jsonl",
    "parse_activity_lines",
    "FEATURE_NAMES",
    "UserFeatureExtractor",
    "extract_user_day_features",
    "InsiderThreatDetector",
    "DetectorConfig",
    "UserVerdict",
    "LLMInsiderAnalyst",
    "InsiderIncidentReport",
    "InsiderPipeline",
    "PipelineResult",
]
