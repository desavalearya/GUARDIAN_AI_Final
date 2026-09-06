"""Behavioral ATO baseline: trusted-sender style drift, not a location claim."""

from __future__ import annotations

import json
import re
from pathlib import Path

from backend.config import settings
from backend.detection.types import DetectorOutput, verdict_from_score as _verdict
from backend.email.parser import ParsedEmail

_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall((text or "").lower()))


def load_baselines() -> dict[str, dict]:
    path = Path(settings.data_dir) / "intel" / "ato_baselines.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("senders", data) if isinstance(data, dict) else {}


def run_ato_baseline(parsed: ParsedEmail) -> DetectorOutput:
    sender = (parsed.sender_address or "").lower()
    baselines = load_baselines()
    base = baselines.get(sender)
    if not base:
        return DetectorOutput(
            detector_name="ato_baseline",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No pre-seeded baseline for this sender.",
            evidence={"sender": sender},
            model_version="ato-baseline-v1",
        )

    expected = set(base.get("tokens") or [])
    current = _tokens(f"{parsed.subject} {parsed.body_plain}")
    overlap = len(expected & current)
    drift = 1.0 - (overlap / max(len(expected), 1))
    unusual = [w for w in ("wire", "gift", "urgent", "beneficiary", "password", "otp", "click") if w in current]
    score = 0.15 + 0.7 * min(max(drift, 0.0), 1.0)
    if unusual:
        score = max(score, 0.8)
    headers = (parsed.raw_headers or "").lower()
    auth_green = "spf=pass" in headers and "dkim=pass" in headers
    explanation = (
        f"Sender has a seeded baseline ({base.get('label', sender)}). "
        f"Token overlap {overlap}/{len(expected)}; drift={drift:.2f}."
    )
    if auth_green and score >= 0.7:
        explanation += " Protocol auth looks green while behavior drifted — HUMAN_REVIEW candidate."
    return DetectorOutput(
        detector_name="ato_baseline",
        raw_score=round(min(score, 0.93), 3),
        verdict=_verdict(score),
        explanation=explanation,
        evidence={
            "sender": sender,
            "overlap": overlap,
            "expected_count": len(expected),
            "unusual": unusual,
            "auth_headers_green": auth_green,
        },
        model_version="ato-baseline-v1",
    )
