"""Pipeline orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .analyst import InsiderIncidentReport, LLMInsiderAnalyst
from .detector import InsiderThreatDetector, UserVerdict
from .events import UserActivity
from .parser import parse_activity_jsonl, parse_activity_lines


@dataclass
class PipelineResult:
    activities: List[UserActivity]
    verdicts: List[UserVerdict]
    report: Optional[InsiderIncidentReport] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "activity_count": len(self.activities),
            "suspicious_count": sum(1 for v in self.verdicts if v.suspicious),
            "verdicts": [v.to_dict() for v in self.verdicts],
            "report": self.report.to_dict() if self.report else None,
        }


@dataclass
class InsiderPipeline:
    detector: InsiderThreatDetector
    analyst: Optional[LLMInsiderAnalyst] = None
    enable_llm: bool = True

    def from_file(self, path: str) -> PipelineResult:
        return self.run(parse_activity_jsonl(path))

    def from_lines(self, lines: Sequence[str]) -> PipelineResult:
        return self.run(parse_activity_lines(lines))

    def run(self, activities: Sequence[UserActivity]) -> PipelineResult:
        acts = list(activities)
        verdicts = self.detector.predict(acts)
        report: Optional[InsiderIncidentReport] = None
        if self.enable_llm and self.analyst is not None:
            suspicious = [v for v in verdicts if v.suspicious]
            if suspicious:
                report = self.analyst.analyse(suspicious, acts)
            else:
                report = InsiderIncidentReport(
                    headline="No suspicious users",
                    archetype="unknown",
                    severity="low",
                    summary="Detector flagged nothing above threshold.",
                    affected_users=[], indicators=[], recommended_actions=[],
                    confidence=0.95, fallback=False,
                )
        return PipelineResult(activities=acts, verdicts=verdicts, report=report)
