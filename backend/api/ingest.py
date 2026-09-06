from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.email.pipeline import ingest_and_analyze
from backend.models import Email
from backend.schemas import EmailDetail, IngestRawRequest

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


def serialize_email(email: Email) -> EmailDetail:
    conf = email.confidence
    dec = email.decision
    return EmailDetail(
        id=email.id,
        received_at=email.received_at,
        sender_address=email.sender_address,
        sender_display_name=email.sender_display_name,
        recipient_address=email.recipient_address,
        subject=email.subject,
        body_plain=email.body_plain,
        direction=email.direction,
        ingestion_path=email.ingestion_path,
        is_duplicate=email.is_duplicate,
        status=email.status,
        urls=[u.raw_url for u in email.urls],
        attachments=[a.filename for a in email.attachments],
        detectors=[
            {
                "detector_name": d.detector_name,
                "raw_score": d.raw_score,
                "verdict": d.verdict,
                "explanation": d.explanation,
                "evidence": d.evidence or {},
                "model_version": d.model_version,
            }
            for d in email.detector_results
        ],
        fused_risk_score=conf.fused_risk_score if conf else None,
        confidence_state=conf.confidence_state if conf else None,
        agreement_metric=conf.agreement_metric if conf else None,
        contributing_detectors=conf.contributing_detectors if conf else {},
        decision=dec.decision if dec else None,
        review_queue=dec.review_queue if dec else None,
        analyst_override=dec.analyst_override if dec else False,
        evidence_sha256=email.evidence_sha256 or "",
        secret_flags=email.secret_flags or {},
        hmac_token_keys=sorted((email.hmac_tokens or {}).keys()),
        retention_days=email.retention_days or 30,
        campaign_id=email.campaign_id,
        case_ref=email.case.case_ref if email.case else None,
        vault_preserved=bool(email.vault and email.vault.preserved),
        custody=[
            {"action": c.action, "role": c.role, "at": c.created_at.isoformat()}
            for c in email.custody_events
        ],
    )


@router.post("/raw", response_model=EmailDetail)
def ingest_raw(
    body: IngestRawRequest,
    db: Session = Depends(get_db),
    x_ingest_key: str | None = Header(default=None, alias="X-Ingest-Key"),
) -> EmailDetail:
    expected = settings.ingest_api_key
    if expected and x_ingest_key != expected:
        raise HTTPException(status_code=401, detail="Invalid ingest key")
    email = ingest_and_analyze(
        db,
        body.raw_message,
        direction=body.direction,
        ingestion_path=body.ingestion_path,
    )
    email = db.query(Email).filter(Email.id == email.id).one()
    return serialize_email(email)


@router.get("/{email_id}", response_model=EmailDetail)
def get_ingested(email_id: UUID, db: Session = Depends(get_db)) -> EmailDetail:
    email = db.query(Email).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Email not found")
    return serialize_email(email)
