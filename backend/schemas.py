from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="analyst", pattern="^(user|viewer|analyst|admin)$")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


class PingEnqueueResponse(BaseModel):
    task_id: str
    status: str = "queued"


class CeleryPingResponse(BaseModel):
    id: UUID
    message: str
    task_id: str
    triggered_by_user_id: UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ComposeRequest(BaseModel):
    recipient: EmailStr = "user@example.com"
    subject: str = Field(min_length=1, max_length=998, pattern=r"^[^\r\n]*$")
    body: str = Field(max_length=500_000)


class PeerComposeRequest(BaseModel):
    """Company B (Mailpit side) → Guardian mailbox."""

    recipient: EmailStr | None = None
    subject: str = Field(min_length=1, max_length=998, pattern=r"^[^\r\n]*$")
    body: str = Field(max_length=500_000)
    mirror_to_mailpit: bool = True


class IngestRawRequest(BaseModel):
    raw_message: str = Field(max_length=15_000_000)
    direction: str = Field(default="inbound", pattern="^(inbound|outbound)$")
    ingestion_path: str = Field(default="api", max_length=32)


class DetectorOut(BaseModel):
    detector_name: str
    raw_score: float
    verdict: str
    explanation: str
    evidence: dict
    model_version: str


class EmailListItem(BaseModel):
    id: UUID
    received_at: datetime
    sender_address: str
    recipient_address: str
    subject: str
    direction: str
    decision: str | None = None
    fused_risk_score: float | None = None
    confidence_state: str | None = None
    review_queue: str | None = None
    ingestion_path: str | None = None


class EmailDetail(BaseModel):
    id: UUID
    received_at: datetime
    sender_address: str
    sender_display_name: str
    recipient_address: str
    subject: str
    body_plain: str
    raw_headers: str = ""
    direction: str
    ingestion_path: str
    is_duplicate: bool
    status: str
    urls: list[str]
    attachments: list[str]
    detectors: list[DetectorOut]
    fused_risk_score: float | None = None
    confidence_state: str | None = None
    agreement_metric: float | None = None
    contributing_detectors: dict = {}
    decision: str | None = None
    review_queue: str | None = None
    analyst_override: bool = False
    evidence_sha256: str = ""
    secret_flags: dict = {}
    hmac_token_keys: list[str] = []
    retention_days: int = 30
    analysis_mode: str = "adaptive"
    fast_path_ms: int = 0
    deep_path_ms: int = 0
    total_analysis_ms: int = 0
    deep_status: str = "complete"
    models_run: list[str] = []
    siem_status: str = "disabled"
    unlock_status: str | None = None
    fraud_dna: dict | None = None
    campaign_id: UUID | None = None
    case_ref: str | None = None
    vault_preserved: bool = False
    custody: list[dict] = []


class ReviewAction(BaseModel):
    notes: str | None = None


class LabTextRequest(BaseModel):
    text: str


class LabUrlRequest(BaseModel):
    url: str


class LabScoreResponse(BaseModel):
    detector_name: str
    raw_score: float
    verdict: str
    explanation: str
    evidence: dict
    model_version: str
