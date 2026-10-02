"""Adaptive fast/deep inference orchestration for SMTP-safe latency."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from backend.config import settings
from backend.detection.engine import (
    _heuristic_phishing_text,
    run_deep_detectors,
    run_fast_detectors,
)
from backend.detection.types import DetectorOutput
from backend.email.parser import ParsedEmail
from backend.risk.engine import apply_booster, compute_confidence, compute_risk


@dataclass
class DetectionRun:
    outputs: list[DetectorOutput]
    analysis_mode: str
    fast_path_ms: int
    deep_path_ms: int
    total_ms: int
    deep_status: str
    models_run: list[str]


def _has_document(parsed: ParsedEmail) -> bool:
    return any(
        item.filename.lower().endswith(
            (".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx")
        )
        or "pdf" in item.mime_type
        or "officedocument" in item.mime_type
        for item in parsed.attachments
    )


def _needs_inline_deep(
    parsed: ParsedEmail,
    fast_outputs: list[DetectorOutput],
    direction: str,
) -> bool:
    if _has_document(parsed):
        return True
    risk, _ = compute_risk(fast_outputs)
    risk = apply_booster(risk, fast_outputs, direction)
    confidence, _ = compute_confidence(fast_outputs)
    cheap_text = _heuristic_phishing_text(parsed)
    return (
        confidence == "UNCERTAIN"
        or settings.deep_sync_min_risk <= risk <= settings.deep_sync_max_risk
        or cheap_text.raw_score >= 0.4
        or any(item.raw_score >= 0.4 for item in fast_outputs)
    )


def _skipped_deep_outputs(parsed: ParsedEmail) -> list[DetectorOutput]:
    outputs = [
        DetectorOutput(
            detector_name="xlm_r_phishing",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="Heavy text model deferred by adaptive fast-path policy.",
            evidence={"backend": "adaptive-deferred"},
            model_version="adaptive-deferred-v1",
        )
    ]
    if parsed.attachments:
        outputs.append(
            DetectorOutput(
                detector_name="doc_attachment_threat",
                raw_score=0.0,
                verdict="not_applicable",
                explanation="No relevant Office/PDF attachment required deep analysis.",
                evidence={"backend": "adaptive-skip"},
                model_version="adaptive-skip-v1",
            )
        )
    return outputs


def _model_versions(outputs: list[DetectorOutput]) -> list[str]:
    return sorted(
        {
            item.model_version
            for item in outputs
            if item.verdict != "not_applicable" and item.model_version
        }
    )


def run_detection(
    parsed: ParsedEmail,
    direction: str,
    *,
    force_deep: bool = False,
) -> DetectionRun:
    started = perf_counter()
    fast_started = perf_counter()
    fast_outputs = run_fast_detectors(parsed, direction)
    fast_ms = round((perf_counter() - fast_started) * 1000)

    mode = settings.analysis_mode.strip().lower()
    if mode not in {"adaptive", "full", "fast"}:
        mode = "adaptive"
    run_deep = force_deep or mode == "full" or (mode == "adaptive" and _needs_inline_deep(parsed, fast_outputs, direction))

    deep_ms = 0
    if run_deep:
        deep_started = perf_counter()
        deep_outputs = run_deep_detectors(parsed)
        deep_ms = round((perf_counter() - deep_started) * 1000)
        deep_status = "complete"
    else:
        deep_outputs = _skipped_deep_outputs(parsed)
        deep_status = "queued" if mode == "adaptive" and settings.async_deep_enabled else "skipped"

    outputs = fast_outputs + deep_outputs
    return DetectionRun(
        outputs=outputs,
        analysis_mode=mode,
        fast_path_ms=fast_ms,
        deep_path_ms=deep_ms,
        total_ms=round((perf_counter() - started) * 1000),
        deep_status=deep_status,
        models_run=_model_versions(outputs),
    )
