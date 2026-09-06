from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DetectorOutput:
    detector_name: str
    raw_score: float
    verdict: str
    explanation: str
    evidence: dict = field(default_factory=dict)
    model_version: str = "heuristic-v1"


def verdict_from_score(score: float, applicable: bool = True) -> str:
    if not applicable:
        return "not_applicable"
    if score >= 0.75:
        return "malicious"
    if score >= 0.4:
        return "suspicious"
    return "clean"
