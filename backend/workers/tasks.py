import uuid
from datetime import datetime, timedelta, timezone

from backend.database import SessionLocal
from backend.models import CeleryPing, Email
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
