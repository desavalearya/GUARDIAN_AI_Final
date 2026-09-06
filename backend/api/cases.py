from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.deps import require_roles
from backend.api.ingest import serialize_email
from backend.cases.service import (
    add_custody,
    ensure_case,
    fir_pack,
    masked_report,
    unlock_raw,
)
from backend.database import get_db
from backend.models import Campaign, ComplaintCase, Decision, Email, User
from backend.privacy.redact import redact_text
from backend.schemas import EmailDetail

router = APIRouter(prefix="/api/v1/soc", tags=["soc-cases"])


class IntakeRequest(BaseModel):
    victim_mobile: str = ""
    amount_lost: str = ""
    bank: str = ""
    incident_date: str = ""
    district: str = "MH"
    retention_days: int = Field(default=30, ge=1, le=3650)


class CaseOut(BaseModel):
    id: UUID
    case_ref: str
    email_id: UUID
    subject: str
    sender_address: str
    decision: str | None = None
    victim_mobile: str
    amount_lost: str
    bank: str
    incident_date: str
    district: str
    status: str
    campaign_id: UUID | None = None


def _case_out(case: ComplaintCase) -> CaseOut:
    email = case.email
    return CaseOut(
        id=case.id,
        case_ref=case.case_ref,
        email_id=case.email_id,
        subject=email.subject if email else "",
        sender_address=email.sender_address if email else "",
        decision=email.decision.decision if email and email.decision else None,
        victim_mobile=case.victim_mobile,
        amount_lost=case.amount_lost,
        bank=case.bank,
        incident_date=case.incident_date,
        district=case.district,
        status=case.status,
        campaign_id=email.campaign_id if email else None,
    )


@router.get("/alerts")
def alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> dict:
    del current_user
    rows = (
        db.query(Email)
        .join(Decision)
        .filter(Decision.decision.in_(["HARD_BLOCK", "BLOCK"]))
        .order_by(Email.received_at.desc())
        .limit(8)
        .all()
    )
    return {
        "count": len(rows),
        "items": [
            {
                "id": str(e.id),
                "subject": e.subject,
                "decision": e.decision.decision if e.decision else None,
                "from": e.sender_address,
            }
            for e in rows
        ],
    }


@router.get("/cases", response_model=list[CaseOut])
def list_cases(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> list[CaseOut]:
    del current_user
    rows = db.query(ComplaintCase).order_by(ComplaintCase.created_at.desc()).limit(200).all()
    return [_case_out(c) for c in rows]


@router.post("/emails/{email_id}/intake", response_model=CaseOut)
def intake(
    email_id: UUID,
    body: IntakeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> CaseOut:
    email = db.query(Email).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Email not found")
    mobile = redact_text(body.victim_mobile).text if body.victim_mobile else "[MOBILE]"
    case = ensure_case(
        db,
        email,
        victim_mobile=mobile,
        amount_lost=body.amount_lost,
        bank=body.bank,
        incident_date=body.incident_date,
        district=body.district or "MH",
    )
    case.victim_mobile = mobile
    case.amount_lost = body.amount_lost
    case.bank = body.bank
    case.incident_date = body.incident_date
    case.district = body.district or case.district
    email.retention_days = body.retention_days
    add_custody(
        db,
        email.id,
        "case_updated",
        actor_id=current_user.id,
        role=current_user.role,
        detail={"case_ref": case.case_ref},
    )
    db.commit()
    db.refresh(case)
    return _case_out(case)


@router.get("/emails/{email_id}/report")
def forensic_report(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> dict:
    email = db.query(Email).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    add_custody(db, email.id, "exported", actor_id=current_user.id, role=current_user.role)
    db.commit()
    return masked_report(email)


@router.get("/emails/{email_id}/fir")
def fir_notes(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> dict:
    del current_user
    email = db.query(Email).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    return fir_pack(email)


@router.post("/emails/{email_id}/preserve", response_model=EmailDetail)
def preserve_for_fir(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> EmailDetail:
    email = db.query(Email).filter(Email.id == email_id).one_or_none()
    if email is None or email.vault is None:
        raise HTTPException(status_code=404, detail="No vaulted exhibit")
    email.vault.preserved = True
    add_custody(db, email.id, "preserved", actor_id=current_user.id, role=current_user.role)
    db.commit()
    db.refresh(email)
    return serialize_email(email)


@router.post("/emails/{email_id}/unlock")
def unlock_exhibit(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> dict:
    email = db.query(Email).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    try:
        raw = unlock_raw(db, email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    add_custody(db, email.id, "unlocked", actor_id=current_user.id, role=current_user.role)
    db.commit()
    return {"raw_message": raw, "warning": "IO unlock logged. Do not forward cleartext secrets."}


@router.get("/campaigns")
def campaigns(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> list[dict]:
    del current_user
    out = []
    for camp in db.query(Campaign).all():
        out.append(
            {
                "id": str(camp.id),
                "name": camp.name,
                "keys": (camp.keys or {}).get("keys") or [],
                "email_count": len(camp.emails or []),
                "subjects": [e.subject for e in (camp.emails or [])[:8]],
            }
        )
    return out


@router.get("/map-points")
def map_points(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> list[dict]:
    del current_user
    points = []
    for email in db.query(Email).order_by(Email.received_at.desc()).limit(80).all():
        origin = next((d for d in email.detector_results if d.detector_name == "origin_infra"), None)
        geo = (origin.evidence or {}).get("geo") if origin else None
        if not geo or geo.get("latitude") is None:
            continue
        points.append(
            {
                "id": str(email.id),
                "lat": geo.get("latitude"),
                "lon": geo.get("longitude"),
                "label": f"{geo.get('city') or ''} {geo.get('country') or ''}".strip(),
                "asn": origin.evidence.get("aso") if origin else "",
                "class": origin.evidence.get("infra_class") if origin else "",
                "decision": email.decision.decision if email.decision else None,
                "note": "Probable originating infrastructure (GeoLite2), not attacker residence.",
            }
        )
    return points
