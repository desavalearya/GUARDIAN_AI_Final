from celery import Celery

from backend.config import settings

celery_app = Celery(
    "guardian",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    imports=("backend.workers.tasks",),
    beat_schedule={
        "enforce-retention-hourly": {
            "task": "backend.workers.tasks.enforce_retention",
            "schedule": 3600.0,
        },
    },
)
