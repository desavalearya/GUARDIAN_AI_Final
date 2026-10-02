from __future__ import annotations

import uuid

import redis
from sqlalchemy.orm import Session

from backend.cases.service import add_custody, attach_campaign, ensure_case, store_vault
from backend.config import settings
from backend.detection.types import DetectorOutput
from backend.detection.orchestrator import DetectionRun, run_detection
from backend.email.parser import ParsedEmail, parse_raw_email
from backend.models import (
    AuditLog,
    ConfidenceScore,
    Decision,
    DetectorResult,
    Email,
    EmailAttachment,
    EmailUrl,
    Organization,
)
from backend.privacy.redact import evidence_sha256, redact_text, redact_url, sanitize_evidence
from backend.risk.engine import apply_booster, compute_confidence, compute_risk, decide

_redis = None


def redis_client():
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis


def _truncate(value: str | None, limit: int) -> str:
    text = value or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def persist_parsed(
    db: Session,
    parsed: ParsedEmail,
    direction: str,
    ingestion_path: str,
    *,
    evidence_id: str,
    flags: dict,
    tokens: dict,
    is_duplicate: bool = False,
    detection_run: DetectionRun | None = None,
    organization_id: uuid.UUID | None = None,
) -> Email:
    body = redact_text(parsed.body_plain)
    html = redact_text(parsed.body_html or "")
    headers = redact_text(parsed.raw_headers)
    subject = redact_text(parsed.subject)
    display = redact_text(parsed.sender_display_name)
    flags = {
        **flags,
        **{k: flags.get(k) or body.flags.get(k) or html.flags.get(k) or subject.flags.get(k) for k in body.flags},
    }
    tokens = {**tokens, **body.tokens, **html.tokens, **subject.tokens}

    email = Email(
        sender_address=_truncate(parsed.sender_address, 320),
        sender_display_name=_truncate(display.text, 320),
        recipient_address=_truncate(parsed.recipient_address or "user@example.com", 320),
        subject=_truncate(subject.text, 998),
        body_plain=body.text,
        body_html=html.text or None,
        direction=direction,
        ingestion_path=_truncate(ingestion_path, 32),
        content_hash_sha256=parsed.content_hash_sha256,
        is_duplicate=is_duplicate,
        raw_headers=headers.text,
        raw_message="",
        status="processing",
        evidence_sha256=evidence_id,
        secret_flags=flags,
        hmac_tokens=tokens,
        retention_days=30,
        analysis_mode=detection_run.analysis_mode if detection_run else "full",
        fast_path_ms=detection_run.fast_path_ms if detection_run else 0,
        deep_path_ms=detection_run.deep_path_ms if detection_run else 0,
        total_analysis_ms=detection_run.total_ms if detection_run else 0,
        deep_status=detection_run.deep_status if detection_run else "complete",
        models_run=detection_run.models_run if detection_run else [],
        organization_id=organization_id,
    )
    db.add(email)
    db.flush()

    for url in parsed.urls:
        db.add(
            EmailUrl(
                email_id=email.id,
                raw_url=_truncate(redact_url(url.raw_url), 2048),
                source=_truncate(url.source, 32),
                domain=_truncate(url.domain, 255),
            )
        )
    for att in parsed.attachments:
        safe_name = redact_text(att.filename).text or "unnamed"
        db.add(
            EmailAttachment(
                email_id=email.id,
                filename=_truncate(safe_name, 255),
                file_hash_sha256=att.sha256,
                mime_type=_truncate(att.mime_type, 128),
                file_size_bytes=att.size,
                storage_note="hash-only",
            )
        )
    return email


def save_detectors(db: Session, email_id: uuid.UUID, outputs: list[DetectorOutput]) -> None:
    for item in outputs:
        db.add(
            DetectorResult(
                email_id=email_id,
                detector_name=item.detector_name,
                raw_score=item.raw_score,
                verdict=item.verdict,
                explanation=redact_text(item.explanation).text,
                evidence=sanitize_evidence(item.evidence or {}),
                model_version=item.model_version,
            )
        )


def save_decision(
    db: Session,
    email: Email,
    outputs: list[DetectorOutput],
) -> Decision:
    state, variance = compute_confidence(outputs)
    risk, contrib = compute_risk(outputs)
    risk = apply_booster(risk, outputs, email.direction)
    decision_value, queue = decide(risk, state)

    conf = email.confidence or ConfidenceScore(email_id=email.id)
    conf.fused_risk_score = risk
    conf.confidence_state = state
    conf.agreement_metric = variance
    conf.contributing_detectors = contrib
    conf.fusion_method_version = "weighted-v1"
    dec = email.decision or Decision(email_id=email.id)
    dec.decision = decision_value
    dec.review_queue = queue
    if email.confidence is None:
        db.add(conf)
    if email.decision is None:
        db.add(dec)
    email.status = "decided"
    return dec


def ingest_and_analyze(
    db: Session,
    raw: str | bytes,
    direction: str = "inbound",
    ingestion_path: str = "api",
    default_recipient: str = "user@example.com",
    organization_id: uuid.UUID | None = None,
) -> Email:
    raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    evidence_id = evidence_sha256(raw_bytes)
    cache_key = f"email:hash:{evidence_id}"
    r = redis_client()
    # Read-only duplicate probe. Marker is written only after a successful commit.
    is_dup = bool(r.get(cache_key))

    parsed = parse_raw_email(raw, default_recipient=default_recipient)
    if organization_id is None:
        recipient_domain = (
            parsed.recipient_address.rsplit("@", 1)[-1].lower()
            if "@" in parsed.recipient_address
            else ""
        )
        organizations = db.query(Organization).all()
        organization = next(
            (org for org in organizations if recipient_domain in (org.domains or [])),
            None,
        ) or next(
            (org for org in organizations if org.slug == settings.default_org_slug),
            None,
        )
        organization_id = organization.id if organization else None
    detection_run = run_detection(parsed, direction)
    from backend.detection.dlp import run_dlp
    from backend.models import DlpPolicy

    dlp_query = db.query(DlpPolicy).filter(DlpPolicy.enabled.is_(True))
    if organization_id:
        dlp_query = dlp_query.filter(DlpPolicy.organization_id == organization_id)
    dlp_output = run_dlp(parsed, direction, dlp_query.all())
    detection_run.outputs.append(dlp_output)
    if dlp_output.verdict != "not_applicable":
        detection_run.models_run = sorted(set(detection_run.models_run) | {dlp_output.model_version})
    outputs = detection_run.outputs
    redacted = redact_text(f"{parsed.subject}\n{parsed.body_plain}")
    email = persist_parsed(
        db,
        parsed,
        direction,
        ingestion_path,
        evidence_id=evidence_id,
        flags=redacted.flags,
        tokens=redacted.tokens,
        is_duplicate=is_dup,
        detection_run=detection_run,
        organization_id=organization_id,
    )
    store_vault(db, email, raw_bytes)
    add_custody(db, email.id, "ingested", role="system", detail={"path": ingestion_path})
    save_detectors(db, email.id, outputs)
    save_decision(db, email, outputs)
    email.siem_status = "queued" if settings.siem_webhook_url else "disabled"
    db.flush()
    email = db.query(Email).filter(Email.id == email.id).one()
    attach_campaign(db, email)
    if email.decision and email.decision.decision in {
        "HARD_BLOCK",
        "BLOCK",
        "QUARANTINE",
        "HUMAN_REVIEW",
    }:
        ensure_case(db, email)
    add_custody(
        db,
        email.id,
        "analyzed",
        role="system",
        detail={"decision": email.decision.decision if email.decision else ""},
    )
    db.commit()
    db.refresh(email)
    try:
        r.setex(cache_key, 60 * 60 * 24 * 7, str(email.id))
    except Exception:
        pass
    if email.deep_status == "queued":
        try:
            from backend.workers.tasks import deep_analyze_email

            deep_analyze_email.delay(str(email.id))
        except Exception:
            # Fast-path delivery must not fail just because the async worker is unavailable.
            email.deep_status = "deferred"
            db.commit()
    if settings.siem_webhook_url:
        try:
            from backend.workers.tasks import emit_siem_event

            emit_siem_event.delay(str(email.id))
        except Exception:
            email.siem_status = "failed"
            db.commit()
    if email.decision and email.decision.decision in {
        "HARD_BLOCK",
        "BLOCK",
        "QUARANTINE",
        "HUMAN_REVIEW",
    }:
        try:
            from backend.workers.tasks import generate_fraud_dna

            generate_fraud_dna.delay(str(email.id))
        except Exception:
            pass
    return email


def write_audit(
    db: Session,
    actor_id: uuid.UUID | None,
    role: str,
    action: str,
    email_id: uuid.UUID | None,
    before: dict | None = None,
    after: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            actor_id=actor_id,
            role=role,
            action=action,
            email_id=email_id,
            before_json=before,
            after_json=after,
        )
    )
