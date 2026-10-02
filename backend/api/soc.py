from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from backend.api.deps import require_roles
from backend.api.ingest import serialize_email
from backend.database import get_db
from backend.email.pipeline import ingest_and_analyze, write_audit
from backend.models import Decision, Email, User
from backend.schemas import EmailDetail, EmailListItem, ReviewAction

router = APIRouter(prefix="/api/v1/soc", tags=["soc"])


def _to_item(email: Email) -> EmailListItem:
    dec = email.decision
    conf = email.confidence
    return EmailListItem(
        id=email.id,
        received_at=email.received_at,
        sender_address=email.sender_address,
        recipient_address=email.recipient_address,
        subject=email.subject,
        direction=email.direction,
        decision=dec.decision if dec else None,
        fused_risk_score=conf.fused_risk_score if conf else None,
        confidence_state=conf.confidence_state if conf else None,
        review_queue=dec.review_queue if dec else None,
        ingestion_path=email.ingestion_path,
    )


@router.post("/upload-eml", response_model=EmailDetail)
async def upload_eml(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> EmailDetail:
    """Analyse a raw .eml through the same pipeline as SMTP ingest."""
    import asyncio

    from backend.config import settings

    name = (file.filename or "complaint.eml").lower()
    if not name.endswith((".eml", ".txt")):
        raise HTTPException(
            status_code=400,
            detail="Upload RFC822 .eml or .txt. Outlook .msg is not supported (convert to .eml first).",
        )
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(raw) > settings.max_attachment_bytes:
        raise HTTPException(status_code=413, detail="File too large")

    def _run() -> Email:
        return ingest_and_analyze(
            db,
            raw,
            direction="inbound",
            ingestion_path="soc_upload",
            default_recipient=current_user.email,
            organization_id=current_user.organization_id,
        )

    email = await asyncio.to_thread(_run)
    email = db.query(Email).filter(Email.id == email.id).one()
    write_audit(
        db,
        current_user.id,
        current_user.role,
        "soc_upload_eml",
        email.id,
        None,
        {"filename": file.filename},
    )
    db.commit()
    return serialize_email(email)


@router.get("/emails", response_model=list[EmailListItem])
def list_emails(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> list[EmailListItem]:
    rows = (
        db.query(Email)
        .filter(Email.organization_id == current_user.organization_id)
        .order_by(Email.received_at.desc())
        .limit(200)
        .all()
    )
    return [_to_item(e) for e in rows]


@router.get("/emails/{email_id}", response_model=EmailDetail)
def email_detail(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> EmailDetail:
    email = (
        db.query(Email)
        .filter(
            Email.id == email_id,
            Email.organization_id == current_user.organization_id,
        )
        .one_or_none()
    )
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    return serialize_email(email)


@router.get("/queues/{queue}", response_model=list[EmailListItem])
def review_queue(
    queue: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> list[EmailListItem]:
    q = (
        db.query(Email)
        .join(Decision)
        .filter(Email.organization_id == current_user.organization_id)
    )
    if queue.upper() == "UNCERTAIN":
        q = q.filter(Decision.review_queue == "UNCERTAIN")
    elif queue.upper() == "HIGH_RISK":
        q = q.filter(Decision.review_queue == "HIGH_RISK")
    else:
        raise HTTPException(status_code=400, detail="queue must be UNCERTAIN or HIGH_RISK")
    return [_to_item(e) for e in q.order_by(Email.received_at.desc()).limit(200).all()]


@router.post("/emails/{email_id}/release", response_model=EmailDetail)
def release(
    email_id: UUID,
    body: ReviewAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> EmailDetail:
    email = (
        db.query(Email)
        .filter(Email.id == email_id, Email.organization_id == current_user.organization_id)
        .one_or_none()
    )
    if email is None or email.decision is None:
        raise HTTPException(status_code=404, detail="Not found")
    before = {"decision": email.decision.decision}
    email.decision.decision = "PASS"
    email.decision.analyst_override = True
    email.decision.analyst_id = current_user.id
    email.decision.analyst_notes = body.notes
    email.decision.review_queue = None
    write_audit(db, current_user.id, current_user.role, "release", email.id, before, {"decision": "PASS"})
    db.commit()
    db.refresh(email)
    return serialize_email(email)


@router.post("/emails/{email_id}/block", response_model=EmailDetail)
def block(
    email_id: UUID,
    body: ReviewAction,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> EmailDetail:
    email = (
        db.query(Email)
        .filter(Email.id == email_id, Email.organization_id == current_user.organization_id)
        .one_or_none()
    )
    if email is None or email.decision is None:
        raise HTTPException(status_code=404, detail="Not found")
    before = {"decision": email.decision.decision}
    email.decision.decision = "BLOCK"
    email.decision.analyst_override = True
    email.decision.analyst_id = current_user.id
    email.decision.analyst_notes = body.notes
    email.decision.review_queue = "HIGH_RISK"
    write_audit(db, current_user.id, current_user.role, "block", email.id, before, {"decision": "BLOCK"})
    db.commit()
    db.refresh(email)
    return serialize_email(email)
