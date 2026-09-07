from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.api.ingest import serialize_email
from backend.database import get_db
from backend.email.parser import build_rfc822
from backend.email.pipeline import ingest_and_analyze
from backend.models import Decision, Email, User
from backend.schemas import ComposeRequest, EmailDetail, EmailListItem

router = APIRouter(prefix="/api/v1/mailbox", tags=["mailbox"])

INBOX_DECISIONS = {"PASS", "SOFT_PASS"}
QUARANTINE_DECISIONS = {"QUARANTINE", "HUMAN_REVIEW"}


def _items(rows: list[Email]) -> list[EmailListItem]:
    out = []
    for email in rows:
        dec = email.decision
        conf = email.confidence
        out.append(
            EmailListItem(
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
            )
        )
    return out


@router.get("/folders/{folder}", response_model=list[EmailListItem])
def list_folder(
    folder: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[EmailListItem]:
    q = db.query(Email).join(Decision, Decision.email_id == Email.id, isouter=True)
    box = current_user.email.lower()
    if folder == "inbox":
        q = q.filter(Email.recipient_address == box, Decision.decision.in_(INBOX_DECISIONS))
    elif folder == "quarantine":
        q = q.filter(Email.recipient_address == box, Decision.decision.in_(QUARANTINE_DECISIONS))
    elif folder == "sent":
        q = q.filter(Email.sender_address == box, Email.direction == "outbound")
    else:
        raise HTTPException(status_code=400, detail="Unknown folder")
    rows = q.order_by(Email.received_at.desc()).limit(100).all()
    return _items(rows)


@router.get("/messages/{email_id}", response_model=EmailDetail)
def read_message(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EmailDetail:
    email = db.query(Email).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    box = current_user.email.lower()
    if email.recipient_address != box and email.sender_address != box and current_user.role not in (
        "analyst",
        "admin",
        "viewer",
    ):
        raise HTTPException(status_code=403, detail="Not your message")
    return serialize_email(email)


@router.post("/compose", response_model=EmailDetail)
def compose(
    body: ComposeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EmailDetail:
    from backend.email.smtp_submit import submit_via_postfix
    from backend.config import settings

    # Prefer domain-aligned From for DKIM signing
    sender = current_user.email
    if settings.mail_domain and not sender.endswith("@" + settings.mail_domain):
        # keep login email for mailbox identity; still send as that address
        pass

    raw = build_rfc822(sender, body.recipient, body.subject, body.body)
    email = ingest_and_analyze(
        db,
        raw,
        direction="outbound",
        ingestion_path="compose",
        default_recipient=body.recipient,
    )
    email = db.query(Email).filter(Email.id == email.id).one()
    decision = email.decision.decision if email.decision else "PASS"

    if decision in {"PASS", "SOFT_PASS"}:
        result = submit_via_postfix(sender, body.recipient, body.subject, body.body)
        if not result.get("ok"):
            raise HTTPException(
                status_code=502,
                detail=f"Guardian allowed the message but Postfix submit failed: {result.get('error')}",
            )
    elif decision in {"BLOCK", "HARD_BLOCK"}:
        raise HTTPException(status_code=403, detail=f"Outbound blocked by Guardian ({decision})")
    # QUARANTINE / HUMAN_REVIEW: stored for analyst; not relayed to internet
    return serialize_email(email)
