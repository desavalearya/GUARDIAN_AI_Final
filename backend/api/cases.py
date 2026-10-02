from __future__ import annotations

from datetime import datetime, timezone
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
from backend.models import Campaign, ComplaintCase, Decision, Email, UnlockRequest, User
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


class UnlockRequestIn(BaseModel):
    justification: str = Field(min_length=8, max_length=500)


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


def _tenant_emails(db: Session, current_user: User):
    return db.query(Email).filter(Email.organization_id == current_user.organization_id)


@router.get("/alerts")
def alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> dict:
    rows = (
        _tenant_emails(db, current_user)
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
    rows = (
        db.query(ComplaintCase)
        .join(Email)
        .filter(Email.organization_id == current_user.organization_id)
        .order_by(ComplaintCase.created_at.desc())
        .limit(200)
        .all()
    )
    return [_case_out(c) for c in rows]


@router.post("/emails/{email_id}/intake", response_model=CaseOut)
def intake(
    email_id: UUID,
    body: IntakeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> CaseOut:
    email = _tenant_emails(db, current_user).filter(Email.id == email_id).one_or_none()
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
    email = _tenant_emails(db, current_user).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    add_custody(db, email.id, "exported", actor_id=current_user.id, role=current_user.role)
    db.commit()
    return masked_report(email)


@router.get("/emails/{email_id}/report.txt")
def forensic_report_text(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
):
    from fastapi.responses import PlainTextResponse

    from backend.cases.service import forensic_assessment_text

    email = _tenant_emails(db, current_user).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    add_custody(db, email.id, "exported_text", actor_id=current_user.id, role=current_user.role)
    db.commit()
    return PlainTextResponse(forensic_assessment_text(email), media_type="text/plain; charset=utf-8")


@router.get("/emails/{email_id}/fir")
def fir_notes(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> dict:
    email = _tenant_emails(db, current_user).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    return fir_pack(email)


@router.post("/emails/{email_id}/preserve", response_model=EmailDetail)
def preserve_for_fir(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> EmailDetail:
    email = _tenant_emails(db, current_user).filter(Email.id == email_id).one_or_none()
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
    email = _tenant_emails(db, current_user).filter(Email.id == email_id).one_or_none()
    if email is None:
        raise HTTPException(status_code=404, detail="Not found")
    approval = (
        db.query(UnlockRequest)
        .filter(
            UnlockRequest.email_id == email.id,
            UnlockRequest.status == "approved",
        )
        .order_by(UnlockRequest.requested_at.desc())
        .first()
    )
    if approval is None:
        raise HTTPException(
            status_code=409,
            detail="Dual-control approval required: request unlock, then have another analyst approve it.",
        )
    try:
        raw = unlock_raw(db, email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    approval.status = "consumed"
    approval.consumed_at = datetime.now(timezone.utc)
    add_custody(
        db,
        email.id,
        "unlocked",
        actor_id=current_user.id,
        role=current_user.role,
        detail={"request_id": str(approval.id), "approved_by": str(approval.approved_by)},
    )
    db.commit()
    return {
        "raw_message": raw,
        "warning": "Dual-control unlock logged. Do not forward cleartext secrets.",
    }


@router.post("/emails/{email_id}/unlock/request")
def request_unlock(
    email_id: UUID,
    body: UnlockRequestIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> dict:
    email = _tenant_emails(db, current_user).filter(Email.id == email_id).one_or_none()
    if email is None or email.vault is None or not email.vault.preserved:
        raise HTTPException(status_code=400, detail="Preserve the exhibit before requesting unlock")
    pending = (
        db.query(UnlockRequest)
        .filter(
            UnlockRequest.email_id == email.id,
            UnlockRequest.status.in_(["pending", "approved"]),
        )
        .first()
    )
    if pending:
        return {"id": str(pending.id), "status": pending.status}
    request = UnlockRequest(
        email_id=email.id,
        requested_by=current_user.id,
        justification=redact_text(body.justification).text,
        status="pending",
    )
    db.add(request)
    db.flush()
    add_custody(
        db,
        email.id,
        "unlock_requested",
        actor_id=current_user.id,
        role=current_user.role,
        detail={"request_id": str(request.id)},
    )
    db.commit()
    return {"id": str(request.id), "status": request.status}


@router.post("/emails/{email_id}/unlock/approve")
def approve_unlock(
    email_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("analyst", "admin")),
) -> dict:
    if _tenant_emails(db, current_user).filter(Email.id == email_id).one_or_none() is None:
        raise HTTPException(status_code=404, detail="Not found")
    request = (
        db.query(UnlockRequest)
        .filter(UnlockRequest.email_id == email_id, UnlockRequest.status == "pending")
        .order_by(UnlockRequest.requested_at.desc())
        .first()
    )
    if request is None:
        raise HTTPException(status_code=404, detail="No pending unlock request")
    if request.requested_by == current_user.id:
        raise HTTPException(status_code=409, detail="A different analyst must approve this unlock")
    request.approved_by = current_user.id
    request.approved_at = datetime.now(timezone.utc)
    request.status = "approved"
    add_custody(
        db,
        email_id,
        "unlock_approved",
        actor_id=current_user.id,
        role=current_user.role,
        detail={"request_id": str(request.id)},
    )
    db.commit()
    return {"id": str(request.id), "status": request.status}


@router.get("/campaigns")
def campaigns(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> list[dict]:
    out = []
    for camp in db.query(Campaign).filter(
        Campaign.organization_id == current_user.organization_id
    ).all():
        out.append(
            {
                "id": str(camp.id),
                "name": camp.name,
                "keys": (camp.keys or {}).get("keys") or [],
                "email_count": len(camp.emails or []),
                "subjects": [e.subject for e in (camp.emails or [])[:8]],
                "dna_summary": camp.dna_summary or {},
                "growth_rate_flag": camp.growth_rate_flag,
            }
        )
    return out


@router.get("/campaigns/graph")
def campaign_graph(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> dict:
    campaigns = db.query(Campaign).filter(
        Campaign.organization_id == current_user.organization_id
    ).all()
    nodes: list[dict] = []
    edges: list[dict] = []
    for campaign in campaigns:
        campaign_id = f"campaign:{campaign.id}"
        nodes.append(
            {
                "id": campaign_id,
                "kind": "campaign",
                "label": campaign.name,
                "count": len(campaign.emails or []),
                "growth_rate_flag": campaign.growth_rate_flag,
            }
        )
        for email in campaign.emails or []:
            email_id = f"email:{email.id}"
            nodes.append(
                {
                    "id": email_id,
                    "kind": "email",
                    "label": email.subject,
                    "decision": email.decision.decision if email.decision else None,
                }
            )
            edges.append({"source": campaign_id, "target": email_id, "kind": "member"})
            if email.fraud_dna and email.fraud_dna.nearest_email_id:
                edges.append(
                    {
                        "source": email_id,
                        "target": f"email:{email.fraud_dna.nearest_email_id}",
                        "kind": "dna_similarity",
                        "weight": email.fraud_dna.similarity,
                    }
                )
    return {"nodes": nodes, "edges": edges}


@router.get("/map-points")
def map_points(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("viewer", "analyst", "admin")),
) -> list[dict]:
    points = []
    for email in (
        _tenant_emails(db, current_user)
        .order_by(Email.received_at.desc())
        .limit(80)
        .all()
    ):
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
