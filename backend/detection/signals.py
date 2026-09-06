"""Impersonation, recon-pixel, SVG/ICS, TOAD / device-code / invoice heuristics."""

from __future__ import annotations

import re
from html import unescape

from backend.detection.types import DetectorOutput, verdict_from_score as _verdict
from backend.detection.url_heuristics import BRANDS, levenshtein
from backend.email.parser import ParsedEmail
HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ѕ": "s",
        "ԁ": "d",
    }
)

TRACK_HINTS = (
    "doubleclick",
    "facebook.com/tr",
    "google-analytics",
    "pixel",
    "open?id=",
    "beacon",
    "tracking",
    "1x1",
)
TOAD_MARKS = (
    "call us",
    "call back",
    "callback",
    "phone this number",
    "speak to",
    "do not click",
    "no link",
    "customer care number",
    "helpline",
)
DEVICE_CODE_MARKS = (
    "microsoft.com/devicelogin",
    "aka.ms/devicelogin",
    "enter the code",
    "device code",
    "use this code to sign in",
)
INVOICE_MARKS = ("invoice", "payment due", "beneficiary", "ifsc", "neft", "rtgs", "gst")
PHONE_RE = re.compile(r"(?:\+91[\s-]?)?[6-9]\d{9}\b")
IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
SVG_SCRIPT_RE = re.compile(r"<script|onload\s*=|javascript:", re.IGNORECASE)


def _fold(text: str) -> str:
    return (text or "").translate(HOMOGLYPHS).lower()


def run_impersonation(parsed: ParsedEmail) -> DetectorOutput:
    display = parsed.sender_display_name or ""
    sender = parsed.sender_address or ""
    domain = sender.split("@")[-1].lower() if "@" in sender else ""
    folded = _fold(f"{display} {sender} {domain}")
    reasons: list[str] = []
    score = 0.08

    if any(ord(ch) > 127 for ch in f"{display}{sender}"):
        score = max(score, 0.7)
        reasons.append("non-ascii-homograph")
    if domain.startswith("xn--") or ".xn--" in domain:
        score = max(score, 0.78)
        reasons.append("punycode-domain")

    for brand in BRANDS:
        if brand in _fold(display) and brand not in domain:
            score = max(score, 0.82)
            reasons.append(f"display-brand-mismatch:{brand}")
        labels = domain.replace("-", ".").split(".")
        for label in labels:
            if label == brand or len(label) < 4:
                continue
            if 0 < levenshtein(label, brand) <= 2:
                score = max(score, 0.86)
                reasons.append(f"lookalike-domain:{brand}")

    if "bank" in folded and not any(b in domain for b in ("sbi", "hdfc", "icici", "axis", "bank")):
        score = max(score, 0.75)
        reasons.append("bank-display-unrelated-domain")

    if not reasons:
        return DetectorOutput(
            detector_name="impersonation",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No impersonation or lookalike brand signal.",
            evidence={"display": display, "domain": domain},
            model_version="impersonation-v1",
        )
    return DetectorOutput(
        detector_name="impersonation",
        raw_score=round(min(score, 0.95), 3),
        verdict=_verdict(score),
        explanation="; ".join(reasons),
        evidence={"display": display, "domain": domain, "reasons": reasons},
        model_version="impersonation-v1",
    )


def run_recon_pixel(parsed: ParsedEmail) -> DetectorOutput:
    html = unescape(parsed.body_html or "")
    if not html and not parsed.urls:
        return DetectorOutput(
            detector_name="recon_pixel",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No HTML images to inspect.",
            evidence={},
            model_version="recon-pixel-v1",
        )
    hits: list[str] = []
    score = 0.08
    for tag in IMG_TAG_RE.findall(html):
        low = tag.lower()
        if 'width="1"' in low or "width='1'" in low or "width=1" in low:
            if 'height="1"' in low or "height='1'" in low or "height=1" in low:
                hits.append("1x1-img")
                score = max(score, 0.72)
        if any(hint in low for hint in TRACK_HINTS):
            hits.append("tracking-host")
            score = max(score, 0.68)
    for item in parsed.urls:
        if any(hint in item.raw_url.lower() for hint in TRACK_HINTS):
            hits.append(item.domain)
            score = max(score, 0.65)
    if not hits:
        return DetectorOutput(
            detector_name="recon_pixel",
            raw_score=0.1,
            verdict="clean",
            explanation="No tracking-pixel pattern found.",
            evidence={"hits": []},
            model_version="recon-pixel-v1",
        )
    return DetectorOutput(
        detector_name="recon_pixel",
        raw_score=round(score, 3),
        verdict=_verdict(score),
        explanation="Recon/tracking pixel indicators: " + ", ".join(sorted(set(hits))),
        evidence={"hits": sorted(set(hits))},
        model_version="recon-pixel-v1",
    )


def run_svg_ics(parsed: ParsedEmail) -> DetectorOutput:
    flags: list[str] = []
    score = 0.08
    for att in parsed.attachments:
        name = att.filename.lower()
        payload = att.payload or b""
        text = payload.decode("utf-8", errors="ignore")
        if name.endswith(".svg") or "svg" in att.mime_type:
            if SVG_SCRIPT_RE.search(text):
                flags.append(f"svg-script:{att.filename}")
                score = max(score, 0.88)
            else:
                flags.append(f"svg-present:{att.filename}")
                score = max(score, 0.25)
        if name.endswith((".ics", ".ical")) or "calendar" in att.mime_type:
            if re.search(r"\b(VALARM|ATTACH|URL:https?://)", text, re.IGNORECASE):
                flags.append(f"ics-abuse:{att.filename}")
                score = max(score, 0.7)
            else:
                flags.append(f"ics-present:{att.filename}")
                score = max(score, 0.2)
    if not flags:
        return DetectorOutput(
            detector_name="svg_ics",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No SVG or calendar attachments.",
            evidence={},
            model_version="svg-ics-v1",
        )
    return DetectorOutput(
        detector_name="svg_ics",
        raw_score=round(score, 3),
        verdict=_verdict(score),
        explanation="; ".join(flags),
        evidence={"flags": flags},
        model_version="svg-ics-v1",
    )


def run_lure_heuristics(parsed: ParsedEmail) -> DetectorOutput:
    text = f"{parsed.subject}\n{parsed.body_plain}\n{parsed.body_html or ''}".lower()
    reasons: list[str] = []
    score = 0.08
    phones = PHONE_RE.findall(f"{parsed.subject}\n{parsed.body_plain}")
    if any(mark in text for mark in TOAD_MARKS) or (phones and not parsed.urls):
        score = max(score, 0.78)
        reasons.append("toad-callback")
    if any(mark in text for mark in DEVICE_CODE_MARKS):
        score = max(score, 0.8)
        reasons.append("device-code")
    if any(mark in text for mark in INVOICE_MARKS):
        known = {"contoso facilities", "office depot", "contoso logistics"}
        try:
            from pathlib import Path
            from backend.config import settings
            import json

            path = Path(settings.data_dir) / "intel" / "invoice_vendors.json"
            if path.exists():
                known = {v.lower() for v in json.loads(path.read_text(encoding="utf-8")).get("vendors", [])}
        except Exception:
            pass
        if "invoice" in text and not any(v in text for v in known):
            score = max(score, 0.62)
            reasons.append("invoice-unknown-vendor")
        if "new beneficiary" in text or "change of account" in text:
            score = max(score, 0.72)
            reasons.append("invoice-beneficiary-drift")
    if not reasons:
        return DetectorOutput(
            detector_name="lure_heuristics",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No TOAD, device-code, or invoice-drift pattern.",
            evidence={"phone_mentioned": bool(phones)},
            model_version="lure-heuristics-v1",
        )
    return DetectorOutput(
        detector_name="lure_heuristics",
        raw_score=round(min(score, 0.92), 3),
        verdict=_verdict(score),
        explanation="; ".join(reasons),
        evidence={"reasons": reasons, "phone_mentioned": bool(phones), "url_count": len(parsed.urls)},
        model_version="lure-heuristics-v1",
    )
