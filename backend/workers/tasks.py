import uuid
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from time import perf_counter

from backend.cases.service import add_custody, ensure_case
from backend.config import settings
from backend.database import SessionLocal
from backend.detection.engine import run_deep_detectors
from backend.email.parser import parse_raw_email
from backend.email.pipeline import save_decision, save_detectors
from backend.models import CeleryPing, DetectorResult, Email
from backend.privacy.vault import decrypt_raw
from backend.workers.celery_app import celery_app


@celery_app.task(name="backend.workers.tasks.ping_db")
def ping_db(user_id: str | None = None) -> dict:
    db = SessionLocal()
    try:
        ping = CeleryPing(
            message="ping_db: skeleton checkpoint",
            task_id=ping_db.request.id or "unknown",
            triggered_by_user_id=uuid.UUID(user_id) if user_id else None,
        )
        db.add(ping)
        db.commit()
        db.refresh(ping)
        return {"ping_id": str(ping.id), "task_id": ping.task_id}
    finally:
        db.close()


@celery_app.task(name="backend.workers.tasks.enforce_retention")
def enforce_retention() -> dict:
    """Drop non-preserved vault ciphertext and scrub bodies past retention_days."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        purged_vault = 0
        scrubbed = 0
        rows = db.query(Email).filter(Email.retention_days.isnot(None)).limit(500).all()
        for email in rows:
            days = int(email.retention_days or 30)
            cutoff = now - timedelta(days=days)
            received = email.received_at
            if received is None or received.tzinfo is None:
                continue
            if received > cutoff:
                continue
            preserved = bool(email.vault and email.vault.preserved)
            if email.vault is not None and not preserved:
                db.delete(email.vault)
                purged_vault += 1
            if not preserved:
                email.body_plain = "[expired — retention policy]"
                email.body_html = None
                email.raw_headers = "[expired — retention policy]"
                scrubbed += 1
        db.commit()
        return {"purged_vault": purged_vault, "scrubbed_bodies": scrubbed}
    finally:
        db.close()


@celery_app.task(
    name="backend.workers.tasks.deep_analyze_email",
    autoretry_for=(RuntimeError,),
    retry_backoff=True,
    max_retries=3,
)
def deep_analyze_email(email_id: str) -> dict:
    """Complete deferred heavy analysis without blocking the SMTP transaction."""
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == uuid.UUID(email_id)).one_or_none()
        if email is None or email.vault is None:
            return {"email_id": email_id, "status": "missing"}
        if email.deep_status == "complete":
            return {"email_id": email_id, "status": "already-complete"}

        email.deep_status = "running"
        db.commit()
        started = perf_counter()
        raw = decrypt_raw(email.vault.ciphertext)
        parsed = parse_raw_email(raw, default_recipient=email.recipient_address)
        deep_outputs = run_deep_detectors(parsed)
        deep_names = [item.detector_name for item in deep_outputs]
        db.query(DetectorResult).filter(
            DetectorResult.email_id == email.id,
            DetectorResult.detector_name.in_(deep_names),
        ).delete(synchronize_session=False)
        save_detectors(db, email.id, deep_outputs)
        db.flush()
        db.expire(email, ["detector_results", "confidence", "decision"])

        save_decision(db, email, list(email.detector_results))
        deep_ms = round((perf_counter() - started) * 1000)
        email.deep_path_ms = deep_ms
        email.total_analysis_ms = int(email.fast_path_ms or 0) + deep_ms
        email.deep_status = "complete"
        email.models_run = sorted(
            set(email.models_run or [])
            | {item.model_version for item in deep_outputs if item.verdict != "not_applicable"}
        )
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
            "deep_analysis_completed",
            role="system",
            detail={"deep_ms": deep_ms, "decision": email.decision.decision if email.decision else ""},
        )
        db.commit()
        if email.decision and email.decision.decision in {
            "HARD_BLOCK",
            "BLOCK",
            "QUARANTINE",
            "HUMAN_REVIEW",
        }:
            generate_fraud_dna.delay(str(email.id))
        return {
            "email_id": email_id,
            "status": "complete",
            "deep_ms": deep_ms,
            "decision": email.decision.decision if email.decision else None,
        }
    except Exception:
        db.rollback()
        email = db.query(Email).filter(Email.id == uuid.UUID(email_id)).one_or_none()
        if email is not None:
            email.deep_status = "failed"
            db.commit()
        raise
    finally:
        db.close()


@celery_app.task(
    name="backend.workers.tasks.emit_siem_event",
    autoretry_for=(RuntimeError,),
    retry_backoff=True,
    max_retries=3,
)
def emit_siem_event(email_id: str) -> dict:
    """Send a privacy-safe, HMAC-signed decision event to the configured SIEM."""
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == uuid.UUID(email_id)).one_or_none()
        if email is None:
            return {"email_id": email_id, "status": "missing"}
        if not settings.siem_webhook_url:
            email.siem_status = "disabled"
            db.commit()
            return {"email_id": email_id, "status": "disabled"}

        payload = {
            "event": "phishproof.email.decision",
            "email_id": str(email.id),
            "evidence_sha256": email.evidence_sha256,
            "sender_domain": email.sender_address.rsplit("@", 1)[-1].lower(),
            "direction": email.direction,
            "decision": email.decision.decision if email.decision else None,
            "risk_score": email.confidence.fused_risk_score if email.confidence else None,
            "confidence_state": email.confidence.confidence_state if email.confidence else None,
            "campaign_id": str(email.campaign_id) if email.campaign_id else None,
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = hmac.new(
            settings.siem_hmac_secret.encode("utf-8"), encoded, hashlib.sha256
        ).hexdigest()
        try:
            import httpx

            response = httpx.post(
                settings.siem_webhook_url,
                content=encoded,
                headers={
                    "Content-Type": "application/json",
                    "X-PhishProof-Signature": f"sha256={signature}",
                },
                timeout=settings.siem_timeout_seconds,
            )
            response.raise_for_status()
        except Exception as exc:
            email.siem_status = "failed"
            db.commit()
            raise RuntimeError(f"SIEM delivery failed: {exc}") from exc
        email.siem_status = "sent"
        add_custody(db, email.id, "siem_event_sent", role="system")
        db.commit()
        return {"email_id": email_id, "status": "sent"}
    finally:
        db.close()


@celery_app.task(
    name="backend.workers.tasks.generate_fraud_dna",
    autoretry_for=(RuntimeError,),
    retry_backoff=True,
    max_retries=2,
)
def generate_fraud_dna(email_id: str) -> dict:
    """Generate post-decision campaign intelligence off the SMTP critical path."""
    from backend.cases.fraud_dna import build_and_cluster

    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == uuid.UUID(email_id)).one_or_none()
        if email is None:
            return {"email_id": email_id, "status": "missing"}
        fingerprint = build_and_cluster(db, email)
        add_custody(
            db,
            email.id,
            "fraud_dna_generated",
            role="system",
            detail={
                "similarity": fingerprint.similarity,
                "nearest_email_id": (
                    str(fingerprint.nearest_email_id) if fingerprint.nearest_email_id else None
                ),
            },
        )
        db.commit()
        return {
            "email_id": email_id,
            "status": "complete",
            "campaign_id": str(email.campaign_id) if email.campaign_id else None,
            "similarity": fingerprint.similarity,
        }
    except Exception as exc:
        db.rollback()
        raise RuntimeError(f"Fraud DNA generation failed: {exc}") from exc
    finally:
        db.close()
