from __future__ import annotations

import statistics

from backend.detection.types import DetectorOutput

INDEPENDENT = {
    "xlm_r_phishing",
    "url_model",
    "credential_detector",
    "sender_auth",
    "malware_scan",
    "doc_attachment_threat",
    "impersonation",
    "ato_baseline",
    "recon_pixel",
    "svg_ics",
}

CONTENT_AGREE = {
    "xlm_r_phishing",
    "url_model",
    "impersonation",
    "malware_scan",
    "doc_attachment_threat",
    "recon_pixel",
    "svg_ics",
}

WEIGHTS = {
    "sender_auth": 0.16,
    "url_model": 0.15,
    "xlm_r_phishing": 0.15,
    "credential_detector": 0.1,
    "malware_scan": 0.1,
    "doc_attachment_threat": 0.1,
    "origin_infra": 0.05,
    "impersonation": 0.1,
    "lure_heuristics": 0.07,
    "ato_baseline": 0.09,
    "recon_pixel": 0.06,
    "svg_ics": 0.07,
}

VARIANCE_UNCERTAIN = 0.08


def _applicable(items: list[DetectorOutput]) -> list[DetectorOutput]:
    return [d for d in items if d.verdict != "not_applicable" and d.detector_name in INDEPENDENT]


def compute_confidence(detectors: list[DetectorOutput]) -> tuple[str, float]:
    active = _applicable(detectors)
    if len(active) < 2:
        return "CONFIDENT", 0.0
    scores = [d.raw_score for d in active]
    variance = statistics.pvariance(scores)
    if variance < VARIANCE_UNCERTAIN:
        return "CONFIDENT", round(variance, 4)
    content_hits = [d for d in active if d.detector_name in CONTENT_AGREE and d.raw_score >= 0.7]
    if len(content_hits) >= 2:
        return "CONFIDENT", round(variance, 4)
    if any(
        d.detector_name in {"url_model", "malware_scan", "doc_attachment_threat", "svg_ics"}
        and d.raw_score >= 0.7
        for d in active
    ):
        return "CONFIDENT", round(variance, 4)
    return "UNCERTAIN", round(variance, 4)


def compute_risk(detectors: list[DetectorOutput]) -> tuple[float, dict]:
    active = [d for d in detectors if d.verdict != "not_applicable" and d.detector_name in WEIGHTS]
    if not active:
        return 5.0, {}
    weight_sum = sum(WEIGHTS[d.detector_name] for d in active)
    weighted = sum(WEIGHTS[d.detector_name] * d.raw_score for d in active) / weight_sum
    contrib = {d.detector_name: round(d.raw_score, 3) for d in active}
    return round(weighted * 100, 2), contrib


def apply_booster(
    risk: float,
    detectors: list[DetectorOutput],
    direction: str,
) -> float:
    by_name = {d.detector_name: d for d in detectors}
    phish = by_name.get("xlm_r_phishing")
    creds = by_name.get("credential_detector")
    malware = by_name.get("malware_scan")
    doc = by_name.get("doc_attachment_threat")

    if malware and malware.raw_score >= 0.9:
        return 99.0
    if doc and doc.raw_score >= 0.85:
        return max(risk, 92.0)
    auth = by_name.get("sender_auth")
    url = by_name.get("url_model")
    if url and url.raw_score >= 0.7:
        if auth and auth.raw_score >= 0.7:
            return max(risk, 92.0)
        imp = by_name.get("impersonation")
        if imp and imp.raw_score >= 0.7:
            return max(risk, 92.0)
        if phish and phish.raw_score >= 0.7:
            return max(risk, 75.0)
        return max(risk, 72.0)
    if phish and creds and phish.raw_score >= 0.7 and creds.raw_score >= 0.7:
        return max(risk, 88.0)
    svg = by_name.get("svg_ics")
    if svg and svg.raw_score >= 0.7:
        return max(risk, 70.0)
    pixel = by_name.get("recon_pixel")
    if pixel and pixel.raw_score >= 0.7:
        return max(risk, 55.0)
    lure = by_name.get("lure_heuristics")
    if (
        lure
        and "toad-callback" in (lure.evidence or {}).get("reasons", [])
        and (not url or url.verdict == "not_applicable")
    ):
        return min(max(risk, 52.0), 68.0)
    qr = by_name.get("image_qr")
    if qr and qr.raw_score >= 0.7:
        return max(risk, 72.0)
    if direction == "outbound" and creds and creds.raw_score >= 0.8:
        return max(risk, 93.0)
    return risk


def decide(risk: float, confidence_state: str) -> tuple[str, str | None]:
    # High-confidence payload risk must not be softened to HUMAN_REVIEW by variance alone.
    if risk >= 91:
        return "HARD_BLOCK", "HIGH_RISK"
    if risk >= 71:
        return "BLOCK", "HIGH_RISK"
    if confidence_state == "UNCERTAIN":
        return "HUMAN_REVIEW", "UNCERTAIN"
    if risk >= 46:
        return "QUARANTINE", "HIGH_RISK"
    if risk >= 21:
        return "SOFT_PASS", None
    return "PASS", None
