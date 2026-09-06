from __future__ import annotations

import uuid

import redis
from sqlalchemy.orm import Session

from backend.cases.service import add_custody, attach_campaign, ensure_case, store_vault
from backend.config import settings
from backend.detection.types import DetectorOutput
from backend.detection.engine import run_all_detectors
from backend.detection.qr import enrich_parsed_with_qr
from backend.email.parser import ParsedEmail, parse_raw_email
from backend.models import (
    AuditLog,
    ConfidenceScore,
    Decision,
    DetectorResult,
    Email,
    EmailAttachment,
    EmailUrl,
)
from backend.privacy.redact import evidence_sha256, redact_text
from backend.risk.engine import apply_booster, compute_confidence, compute_risk, decide

_redis = None


def redis_client():
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis


def persist_parsed(
    db: Session,
    parsed: ParsedEmail,
    direction: str,
    ingestion_path: str,
    *,
    evidence_id: str,
    flags: dict,
    tokens: dict,
) -> Email:
    r = redis_client()
    cache_key = f"email:hash:{evidence_id}"
    is_dup = bool(r.get(cache_key))

    body = redact_text(parsed.body_plain)
    html = redact_text(parsed.body_html or "")
    headers = redact_text(parsed.raw_headers)
    flags = {**flags, **{k: flags.get(k) or body.flags.get(k) or html.flags.get(k) for k in body.flags}}
    tokens = {**tokens, **body.tokens, **html.tokens}

    email = Email(
        sender_address=parsed.sender_address,
        sender_display_name=parsed.sender_display_name,
        recipient_address=parsed.recipient_address or "user@example.com",
        subject=redact_text(parsed.subject).text,
        body_plain=body.text,
        body_html=html.text or None,
        direction=direction,
        ingestion_path=ingestion_path,
        content_hash_sha256=parsed.content_hash_sha256,
        is_duplicate=is_dup,
        raw_headers=headers.text,
        raw_message="",
        status="processing",
        evidence_sha256=evidence_id,
        secret_flags=flags,
        hmac_tokens=tokens,
        retention_days=30,
    )
    db.add(email)
    db.flush()

    for url in parsed.urls:
        db.add(
            EmailUrl(
                email_id=email.id,
                raw_url=url.raw_url,
                source=url.source,
                domain=url.domain,
            )
        )
    for att in parsed.attachments:
        db.add(
            EmailAttachment(
                email_id=email.id,
                filename=att.filename,
                file_hash_sha256=att.sha256,
                mime_type=att.mime_type,
                file_size_bytes=att.size,
                storage_note="hash-only",
            )
        )
    r.setex(cache_key, 60 * 60 * 24 * 7, str(email.id))
    return email


def save_detectors(db: Session, email_id: uuid.UUID, outputs: list[DetectorOutput]) -> None:
    for item in outputs:
        db.add(
            DetectorResult(
                email_id=email_id,
                detector_name=item.detector_name,
                raw_score=item.raw_score,
                verdict=item.verdict,
                explanation=item.explanation,
                evidence=item.evidence,
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

    conf = ConfidenceScore(
        email_id=email.id,
        fused_risk_score=risk,
        confidence_state=state,
        agreement_metric=variance,
        contributing_detectors=contrib,
        fusion_method_version="weighted-v1",
    )
    dec = Decision(
        email_id=email.id,
        decision=decision_value,
        review_queue=queue,
    )
    db.add(conf)
    db.add(dec)
    email.status = "decided"
    return dec


def ingest_and_analyze(
    db: Session,
    raw: str | bytes,
    direction: str = "inbound",
    ingestion_path: str = "api",
    default_recipient: str = "user@example.com",
) -> Email:
    raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    parsed = parse_raw_email(raw, default_recipient=default_recipient)
    enrich_parsed_with_qr(parsed)
    outputs = run_all_detectors(parsed, direction)
    redacted = redact_text(f"{parsed.subject}\n{parsed.body_plain}")
    email = persist_parsed(
        db,
        parsed,
        direction,
        ingestion_path,
        evidence_id=evidence_sha256(raw_bytes),
        flags=redacted.flags,
        tokens=redacted.tokens,
    )
    store_vault(db, email, raw_bytes)
    add_custody(db, email.id, "ingested", role="system", detail={"path": ingestion_path})
    save_detectors(db, email.id, outputs)
    save_decision(db, email, outputs)
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
    add_custody(db, email.id, "analyzed", role="system", detail={"decision": email.decision.decision if email.decision else ""})
    db.commit()
    db.refresh(email)
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
