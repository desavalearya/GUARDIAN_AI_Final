from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.detection import ml_runtime
from backend.detection import url_ml
from backend.email.pipeline import redis_client

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "phishproof-api"}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict:
    checks: dict[str, str] = {}
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"fail:{exc.__class__.__name__}"

    try:
        redis_client().ping()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = f"fail:{exc.__class__.__name__}"

    checks["model_email"] = "ok" if ml_runtime.model_path("email", "config.json").exists() else "missing"
    checks["model_pdf"] = (
        "ok"
        if (ml_runtime.pdf_dir() / "pdf_malware_model.joblib").exists()
        or (ml_runtime.pdf_dir() / "pdf_malware_rf.joblib").exists()
        else "missing"
    )
    checks["model_office"] = "ok" if ml_runtime.model_path("doc", "office_malware_rf.joblib").exists() else "missing"
    checks["model_url"] = "ok" if url_ml.available() else "missing"
    if settings.clamav_enabled:
        try:
            import clamd

            clamd.ClamdNetworkSocket(
                settings.clamav_host,
                settings.clamav_port,
                timeout=settings.clamav_timeout_seconds,
            ).ping()
            checks["clamav"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["clamav"] = f"degraded:{exc.__class__.__name__}"
    else:
        checks["clamav"] = "disabled"

    ok = checks.get("database") == "ok" and checks.get("redis") == "ok"
    return {"status": "ready" if ok else "degraded", "checks": checks, "model_dir": settings.model_dir}
