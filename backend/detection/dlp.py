"""Outbound data-loss prevention rules; findings contain labels, never matched secrets."""

from __future__ import annotations

import re
from collections.abc import Iterable

from backend.detection.types import DetectorOutput, verdict_from_score
from backend.email.parser import ParsedEmail
from backend.models import DlpPolicy

BUILTIN_RULES = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    "jwt": re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b"),
    "aadhaar": re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"),
    "pan": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "payment_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
}


def run_dlp(
    parsed: ParsedEmail,
    direction: str,
    policies: Iterable[DlpPolicy] = (),
) -> DetectorOutput:
    if direction != "outbound":
        return DetectorOutput(
            detector_name="dlp_policy",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="Outbound DLP is not applicable to inbound mail.",
            evidence={"direction": direction},
            model_version="dlp-rules-v1",
        )

    text = f"{parsed.subject}\n{parsed.body_plain}\n{parsed.body_html or ''}"
    hits = [name for name, pattern in BUILTIN_RULES.items() if pattern.search(text)]
    actions: list[str] = []
    for policy in policies:
        if not policy.enabled:
            continue
        try:
            if re.search(policy.pattern, text, re.I):
                hits.append(f"custom:{policy.name}")
                actions.append(policy.action)
        except re.error:
            continue

    critical = any(name in hits for name in {"aws_access_key", "private_key", "jwt"})
    score = 0.98 if critical or "hard_block" in actions else 0.8 if hits else 0.0
    return DetectorOutput(
        detector_name="dlp_policy",
        raw_score=score,
        verdict=verdict_from_score(score, applicable=bool(hits)),
        explanation=(
            f"Outbound DLP matched {len(hits)} protected data class(es)."
            if hits
            else "No outbound protected-data pattern matched."
        ),
        evidence={"classes": sorted(set(hits)), "actions": sorted(set(actions)), "match_count": len(hits)},
        model_version="dlp-rules-v1",
    )
