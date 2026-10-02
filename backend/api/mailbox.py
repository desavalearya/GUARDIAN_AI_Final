from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.api.ingest import serialize_email
from backend.config import settings
from backend.database import get_db
from backend.email.parser import build_rfc822
from backend.email.pipeline import ingest_and_analyze
from backend.models import Decision, Email, User
from backend.schemas import ComposeRequest, EmailDetail, EmailListItem, PeerComposeRequest

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
                ingestion_path=email.ingestion_path,
            )
        )
    return out


@router.get("/folders/{folder}", response_model=list[EmailListItem])
def list_folder(
    folder: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[EmailListItem]:
    q = (
        db.query(Email)
        .join(Decision, Decision.email_id == Email.id, isouter=True)
        .filter(Email.organization_id == current_user.organization_id)
    )
    box = current_user.email.lower()
    if folder == "inbox":
        q = q.filter(Email.recipient_address == box, Decision.decision.in_(INBOX_DECISIONS))
    elif folder == "quarantine":
        q = q.filter(Email.recipient_address == box, Decision.decision.in_(QUARANTINE_DECISIONS))
    elif folder == "sent":
        q = q.filter(Email.sender_address == box, Email.direction == "outbound")
    elif folder == "all":
        q = q.filter(or_(Email.recipient_address == box, Email.sender_address == box))
    else:
        raise HTTPException(status_code=400, detail="Unknown folder")
    rows = q.order_by(Email.received_at.desc()).limit(200).all()
    return _items(rows)


@router.get("/messages/{email_id}", response_model=EmailDetail)
def read_message(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EmailDetail:
    email = (
        db.query(Email)
        .filter(Email.id == email_id, Email.organization_id == current_user.organization_id)
        .one_or_none()
    )
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
    """Guardian Mail → scan → Postfix → Company B Mailpit (when recipient is @company-b.test)."""
    from backend.email.smtp_submit import submit_via_postfix

    sender = current_user.email
    raw = build_rfc822(sender, body.recipient, body.subject, body.body)
    email = ingest_and_analyze(
        db,
        raw,
        direction="outbound",
        ingestion_path="compose",
        default_recipient=body.recipient,
        organization_id=current_user.organization_id,
    )
    email = db.query(Email).filter(Email.id == email.id).one()
    decision = email.decision.decision if email.decision else "PASS"

    if decision in {"PASS", "SOFT_PASS"}:
        from backend.email.link_rewrite import rewrite_text_urls

        result = submit_via_postfix(
            sender,
            body.recipient,
            body.subject,
            rewrite_text_urls(body.body),
        )
        if not result.get("ok"):
            raise HTTPException(
                status_code=502,
                detail=f"Guardian allowed the message but Postfix submit failed: {result.get('error')}",
            )
    elif decision in {"BLOCK", "HARD_BLOCK"}:
        raise HTTPException(status_code=403, detail=f"Outbound blocked by Guardian ({decision})")
    return serialize_email(email)


@router.post("/peer-compose", response_model=dict)
def peer_compose(
    body: PeerComposeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Company B → Guardian two-server path.

    1) Optionally mirror into Mailpit UI so Company B shows the outbound copy.
    2) Submit through Postfix so the milter scans and delivers into Guardian Mail.
    """
    from backend.email.mailpit_client import mirror_to_mailpit
    from backend.email.smtp_submit import submit_via_postfix

    sender = settings.demo_receiver_address
    recipient = (str(body.recipient) if body.recipient else current_user.email).lower()
    mirror = {"ok": True, "skipped": True}
    if body.mirror_to_mailpit:
        mirror = mirror_to_mailpit(
            sender=sender,
            recipient=recipient,
            subject=body.subject,
            body=body.body,
            sender_name="Company B Mail",
        )

    result = submit_via_postfix(sender, recipient, body.subject, body.body)
    if not result.get("ok"):
        raise HTTPException(
            status_code=502,
            detail=f"Company B → Guardian SMTP failed: {result.get('error')}",
        )

    # Milter ingest is async relative to SMTP response; surface recent matching inbound if present.
    recent = (
        db.query(Email)
        .filter(
            Email.organization_id == current_user.organization_id,
            Email.sender_address == sender.lower(),
            Email.recipient_address == recipient,
            Email.subject == body.subject,
        )
        .order_by(Email.received_at.desc())
        .first()
    )
    return {
        "ok": True,
        "from": sender,
        "to": recipient,
        "mailpit_mirror": mirror,
        "postfix": result,
        "scanned_email_id": str(recent.id) if recent else None,
        "note": "Message submitted through Postfix+milter. Refresh Guardian inbox/SOC after a second.",
    }


@router.get("/demo-peers")
def demo_peers(current_user: User = Depends(get_current_user)) -> dict:
    return {
        "guardian_mailbox": current_user.email,
        "company_b_address": settings.demo_receiver_address,
        "company_b_domain": settings.demo_receiver_domain,
        "mailpit_ui": "http://localhost:8025",
        "guardian_mail_ui": "http://localhost:5173",
        "soc_ui": "http://localhost:5174",
    }
