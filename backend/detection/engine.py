from __future__ import annotations

import logging

from backend.detection.qr import enrich_parsed_with_qr
from backend.detection.types import DetectorOutput, verdict_from_score as _verdict
from backend.detection.url_heuristics import score_urls
from backend.email.parser import ParsedEmail
from backend.detection.auth_checks import run_sender_auth
from backend.detection.ato import run_ato_baseline
from backend.detection.origin import run_origin_infra
from backend.detection.signals import (
    run_impersonation,
    run_lure_heuristics,
    run_recon_pixel,
    run_svg_ics,
)

log = logging.getLogger(__name__)

OTP_ALLOW_DOMAINS = ("paypal.com", "chase.com", "bankofamerica.com", "google.com", "okta.com")

PHISH_WORDS = (
    "verify your account",
    "confirm your password",
    "update billing",
    "urgent action",
    "click here",
    "suspended",
    "wire transfer",
    "gift card",
    "otp",
    "one-time password",
    "login immediately",
    "account will be closed",
)


def run_credentials(parsed: ParsedEmail, direction: str) -> DetectorOutput:
    import math
    import re

    text = f"{parsed.subject}\n{parsed.body_plain}"
    patterns = {
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "jwt": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "otp": r"\b\d{6}\b",
    }
    hits = []
    for name, pat in patterns.items():
        if re.search(pat, text):
            hits.append(name)

    high_entropy = False
    for token in re.findall(r"[A-Za-z0-9+/=]{32,}", text):
        probs = [token.count(c) / len(token) for c in set(token)]
        ent = -sum(p * math.log2(p) for p in probs if p)
        if ent >= 4.5:
            high_entropy = True
            break

    domain = parsed.sender_address.split("@")[-1] if "@" in parsed.sender_address else ""
    if direction == "inbound" and hits == ["otp"] and domain in OTP_ALLOW_DOMAINS:
        return DetectorOutput(
            detector_name="credential_detector",
            raw_score=0.05,
            verdict="clean",
            explanation="OTP from allowlisted authenticated-looking sender; inbound not penalized.",
            evidence={"hits": hits, "allowlisted": True},
        )

    if not hits and not high_entropy:
        return DetectorOutput(
            detector_name="credential_detector",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No credential-like patterns in this email.",
            evidence={"hits": [], "high_entropy": False, "direction": direction},
        )

    score = 0.1
    if "private_key" in hits or "aws_key" in hits:
        score = 0.95
    elif "jwt" in hits:
        score = 0.8
    elif high_entropy:
        score = 0.65
    elif "otp" in hits:
        if direction == "inbound" and hits == ["otp"]:
            return DetectorOutput(
                detector_name="credential_detector",
                raw_score=0.0,
                verdict="not_applicable",
                explanation="OTP-like pattern tokenised; inbound OTP is not a credential-leak vote.",
                evidence={"hits": hits, "direction": direction},
            )
        score = 0.45 if direction == "outbound" else 0.25

    return DetectorOutput(
        detector_name="credential_detector",
        raw_score=score,
        verdict=_verdict(score),
        explanation="Detected secret-like content." if score >= 0.4 else "Credential-like patterns were weak.",
        evidence={"hits": hits, "high_entropy": high_entropy, "direction": direction},
    )


def run_url_model(parsed: ParsedEmail) -> DetectorOutput:
    if not parsed.urls:
        return DetectorOutput(
            detector_name="url_model",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No URLs in this email.",
            evidence={"urls": []},
        )

    score, details = score_urls(parsed.urls)
    return DetectorOutput(
        detector_name="url_model",
        raw_score=round(score, 3),
        verdict=_verdict(score),
        explanation=f"Heuristic URL rules on {len(parsed.urls)} URL(s); max={score:.2f}.",
        evidence={"urls": details, "backend": "heuristics-only"},
        model_version="heuristic-url-v2",
    )


def _heuristic_phishing_text(parsed: ParsedEmail) -> DetectorOutput:
    text = f"{parsed.subject} {parsed.body_plain}".lower()
    hits = [w for w in PHISH_WORDS if w in text]
    score = min(0.2 + 0.18 * len(hits), 0.97)
    if "dear customer" in text and "click" in text:
        score = max(score, 0.8)
    return DetectorOutput(
        detector_name="xlm_r_phishing",
        raw_score=round(score, 3),
        verdict=_verdict(score),
        explanation=(
            f"Heuristic phishing language hits: {', '.join(hits)}."
            if hits
            else "No strong phishing-language patterns."
        ),
        evidence={"hits": hits, "backend": "heuristic-fallback"},
        model_version="heuristic-text-v1",
    )


def run_phishing_text(parsed: ParsedEmail) -> DetectorOutput:
    text = f"{parsed.subject}\n{parsed.body_plain}".strip()
    if not text:
        return DetectorOutput(
            detector_name="xlm_r_phishing",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No text to score.",
            evidence={},
        )
    try:
        from backend.detection.ml_runtime import score_text

        result = score_text(text)
        return DetectorOutput(
            detector_name="xlm_r_phishing",
            raw_score=result.phishing_probability,
            verdict=result.verdict,
            explanation=result.explanation,
            evidence={"backend": "xlm-r", "confidence": result.confidence},
            model_version=result.model_version,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("XLM-R unavailable, using text heuristics: %s", exc)
        return _heuristic_phishing_text(parsed)


def run_image_qr(parsed: ParsedEmail, qr_report: dict | None = None) -> DetectorOutput:
    report = qr_report or {}
    image_count = int(report.get("image_count") or 0)
    if image_count == 0 and not any(
        a.mime_type.startswith("image/")
        or a.filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif"))
        for a in parsed.attachments
    ):
        return DetectorOutput(
            detector_name="image_qr",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No images attached.",
            evidence=report,
        )

    qr_urls = list(report.get("urls") or [])
    if qr_urls:
        from backend.detection.url_heuristics import score_one_url
        from backend.email.parser import _domain

        scores = [score_one_url(u, _domain(u))[0] for u in qr_urls]
        score = max(scores)
        return DetectorOutput(
            detector_name="image_qr",
            raw_score=round(score, 3),
            verdict=_verdict(score),
            explanation=f"Decoded {len(qr_urls)} QR URL(s); scored by URL heuristics.",
            evidence=report,
            model_version="qr-url-v1",
        )

    decoder = report.get("decoder") or "none"
    if decoder == "none":
        return DetectorOutput(
            detector_name="image_qr",
            raw_score=0.15,
            verdict="clean",
            explanation="Images present; QR decoder library not installed in this runtime.",
            evidence=report,
            model_version="qr-stub",
        )
    return DetectorOutput(
        detector_name="image_qr",
        raw_score=0.1,
        verdict="clean",
        explanation="Images scanned; no QR URL decoded.",
        evidence=report,
        model_version="qr-url-v1",
    )


def run_malware(parsed: ParsedEmail) -> DetectorOutput:
    if not parsed.attachments:
        return DetectorOutput(
            detector_name="malware_scan",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No attachments.",
            evidence={},
        )
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    hits = []
    for att in parsed.attachments:
        if eicar in att.payload or att.filename.upper().endswith(".EICAR"):
            hits.append(att.filename)
        if att.filename.lower().endswith((".exe", ".dll", ".scr", ".js")):
            hits.append(att.filename)
    score = 0.98 if hits else 0.08
    return DetectorOutput(
        detector_name="malware_scan",
        raw_score=score,
        verdict=_verdict(score),
        explanation="EICAR/executable signature hit." if hits else "No signature hits (heuristic; ClamAV not wired).",
        evidence={"hits": hits},
        model_version="heuristic-malware-v1",
    )


def _heuristic_doc(parsed: ParsedEmail) -> DetectorOutput:
    docs = [
        a
        for a in parsed.attachments
        if a.filename.lower().endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"))
        or "pdf" in a.mime_type
        or "officedocument" in a.mime_type
    ]
    if not parsed.attachments:
        return DetectorOutput(
            detector_name="doc_attachment_threat",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No attachments.",
            evidence={},
        )
    if not docs:
        return DetectorOutput(
            detector_name="doc_attachment_threat",
            raw_score=0.1,
            verdict="clean",
            explanation="Attachments present but not Office/PDF.",
            evidence={"count": len(parsed.attachments)},
        )

    flags = []
    score = 0.1
    for att in docs:
        name = att.filename.lower()
        declared_pdf = "pdf" in att.mime_type or name.endswith(".pdf")
        looks_pdf = att.payload[:5] == b"%PDF-"
        if declared_pdf and not looks_pdf and att.size > 0:
            flags.append("mime_mismatch_or_corrupt_pdf")
            score = max(score, 0.7)
        if b"/JavaScript" in att.payload or b"/JS" in att.payload:
            flags.append("pdf_javascript")
            score = max(score, 0.8)
        if b"/OpenAction" in att.payload or b"/Launch" in att.payload:
            flags.append("pdf_openaction_or_launch")
            score = max(score, 0.85)
        if b"vbaProject.bin" in att.payload or b"Auto_Open" in att.payload or b"autoexec" in att.payload.lower():
            flags.append("office_macro")
            score = max(score, 0.9)
        if declared_pdf and att.size < 20:
            flags.append("truncated_pdf")
            score = max(score, 0.65)

    return DetectorOutput(
        detector_name="doc_attachment_threat",
        raw_score=round(score, 3),
        verdict=_verdict(score),
        explanation="; ".join(flags) if flags else "Office/PDF structure looks benign (heuristic).",
        evidence={"flags": flags, "files": [d.filename for d in docs], "backend": "heuristic-fallback"},
        model_version="heuristic-doc-v1",
    )


def run_doc_attachment(parsed: ParsedEmail) -> DetectorOutput:
    docs = [
        a
        for a in parsed.attachments
        if a.filename.lower().endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"))
        or "pdf" in a.mime_type
        or "officedocument" in a.mime_type
    ]
    if not parsed.attachments:
        return DetectorOutput(
            detector_name="doc_attachment_threat",
            raw_score=0.0,
            verdict="not_applicable",
            explanation="No attachments.",
            evidence={},
        )
    if not docs:
        return DetectorOutput(
            detector_name="doc_attachment_threat",
            raw_score=0.1,
            verdict="clean",
            explanation="Attachments present but not Office/PDF.",
            evidence={"count": len(parsed.attachments)},
        )

    try:
        from backend.detection.ml_runtime import score_office, score_pdf
    except Exception as exc:  # noqa: BLE001
        log.warning("Attachment ML import failed: %s", exc)
        return _heuristic_doc(parsed)

    file_scores = []
    evidence_files = []
    max_score = 0.0
    versions = []
    for att in docs:
        name = att.filename.lower()
        try:
            if name.endswith(".pdf") or "pdf" in att.mime_type:
                result = score_pdf(att.payload, att.filename)
            else:
                result = score_office(att.payload, att.filename)
            file_scores.append(result.malicious_probability)
            max_score = max(max_score, result.malicious_probability)
            versions.append(result.model_version)
            evidence_files.append(
                {
                    "filename": att.filename,
                    "score": result.malicious_probability,
                    "verdict": result.verdict,
                    "explanation": result.explanation,
                    "model": result.model_version,
                }
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Attachment model failed for %s: %s", att.filename, exc)
            fallback = _heuristic_doc(parsed)
            evidence_files.append(
                {"filename": att.filename, "error": str(exc), "heuristic_score": fallback.raw_score}
            )
            max_score = max(max_score, fallback.raw_score)

    if not evidence_files:
        return _heuristic_doc(parsed)

    return DetectorOutput(
        detector_name="doc_attachment_threat",
        raw_score=round(max_score, 3),
        verdict=_verdict(max_score),
        explanation="; ".join(item.get("explanation", "") for item in evidence_files if item.get("explanation")),
        evidence={"files": evidence_files, "backend": "ml"},
        model_version="+".join(sorted(set(versions))) or "doc-ml",
    )


def run_all_detectors(parsed: ParsedEmail, direction: str) -> list[DetectorOutput]:
    qr_report = enrich_parsed_with_qr(parsed)
    return [
        run_sender_auth(parsed),
        run_phishing_text(parsed),
        run_url_model(parsed),
        run_credentials(parsed, direction),
        run_image_qr(parsed, qr_report),
        run_malware(parsed),
        run_doc_attachment(parsed),
        run_origin_infra(parsed),
        run_impersonation(parsed),
        run_recon_pixel(parsed),
        run_svg_ics(parsed),
        run_lure_heuristics(parsed),
        run_ato_baseline(parsed),
    ]
