from __future__ import annotations

import base64
import hmac

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.deps import require_roles
from backend.api.ingest import serialize_email
from backend.config import settings
from backend.database import get_db
from backend.email.pipeline import ingest_and_analyze
from backend.models import Email, Organization, User
from backend.schemas import EmailDetail

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])


class ConnectorMessage(BaseModel):
    event_id: str = Field(min_length=1, max_length=256)
    raw_message_b64: str = Field(min_length=1, max_length=20_000_000)
    organization_slug: str = Field(default="default", max_length=64)
    direction: str = Field(default="inbound", pattern="^(inbound|outbound)$")


@router.get("/status")
def connector_status(
    current_user: User = Depends(require_roles("admin")),
) -> dict:
    del current_user
    return {
        "microsoft_365": {
            "ready": bool(settings.m365_tenant_id and settings.m365_client_id),
            "mode": "webhook/MIME ingest",
        },
        "google_workspace": {
            "ready": bool(settings.google_service_account_file),
            "mode": "webhook/MIME ingest",
        },
        "generic_webhook": {"ready": bool(settings.connector_webhook_secret)},
        "note": "Provider credentials are required before external activation; no connector is deployed automatically.",
    }


@router.post("/{provider}/messages", response_model=EmailDetail)
def connector_message(
    provider: str,
    body: ConnectorMessage,
    db: Session = Depends(get_db),
    x_connector_secret: str | None = Header(default=None, alias="X-Connector-Secret"),
) -> EmailDetail:
    if provider not in {"m365", "google", "generic"}:
        raise HTTPException(status_code=404, detail="Unknown connector")
    if not hmac.compare_digest(
        x_connector_secret or "",
        settings.connector_webhook_secret,
    ):
        raise HTTPException(status_code=401, detail="Invalid connector secret")
    organization = db.query(Organization).filter(
        Organization.slug == body.organization_slug
    ).one_or_none()
    if organization is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    try:
        raw = base64.b64decode(body.raw_message_b64, validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid base64 MIME message") from exc
    if len(raw) > settings.max_attachment_bytes:
        raise HTTPException(status_code=413, detail="Message too large")
    email = ingest_and_analyze(
        db,
        raw,
        direction=body.direction,
        ingestion_path=f"{provider}_webhook",
        organization_id=organization.id,
    )
    email = db.query(Email).filter(Email.id == email.id).one()
    return serialize_email(email)
