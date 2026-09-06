import uuid

from backend.database import SessionLocal
from backend.models import CeleryPing
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
