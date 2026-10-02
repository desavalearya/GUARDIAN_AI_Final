import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    domains: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="analyst")
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    pings: Mapped[list["CeleryPing"]] = relationship(back_populates="triggered_by")


class CeleryPing(Base):
    __tablename__ = "celery_pings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    task_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    triggered_by: Mapped[User | None] = relationship(back_populates="pings")


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    sender_address: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    sender_display_name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    recipient_address: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    subject: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_plain: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    direction: Mapped[str] = mapped_column(String(16), nullable=False, default="inbound")
    ingestion_path: Mapped[str] = mapped_column(String(32), nullable=False, default="api")
    content_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    raw_headers: Mapped[str] = mapped_column(Text, nullable=False, default="")
    raw_message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="processing")
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    secret_flags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    hmac_tokens: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    analysis_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="adaptive")
    fast_path_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deep_path_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_analysis_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deep_status: Mapped[str] = mapped_column(String(16), nullable=False, default="complete")
    models_run: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    siem_status: Mapped[str] = mapped_column(String(16), nullable=False, default="disabled")
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, index=True
    )
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("campaigns.id"), nullable=True
    )

    urls: Mapped[list["EmailUrl"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    attachments: Mapped[list["EmailAttachment"]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )
    detector_results: Mapped[list["DetectorResult"]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )
    confidence: Mapped["ConfidenceScore | None"] = relationship(
        back_populates="email", uselist=False, cascade="all, delete-orphan"
    )
    decision: Mapped["Decision | None"] = relationship(
        back_populates="email", uselist=False, cascade="all, delete-orphan"
    )
    campaign: Mapped["Campaign | None"] = relationship(back_populates="emails")
    case: Mapped["ComplaintCase | None"] = relationship(
        back_populates="email", uselist=False, cascade="all, delete-orphan"
    )
    vault: Mapped["EvidenceVault | None"] = relationship(
        back_populates="email", uselist=False, cascade="all, delete-orphan"
    )
    custody_events: Mapped[list["CustodyEvent"]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )
    unlock_requests: Mapped[list["UnlockRequest"]] = relationship(
        back_populates="email", cascade="all, delete-orphan"
    )
    fraud_dna: Mapped["FraudFingerprint | None"] = relationship(
        back_populates="email", uselist=False, cascade="all, delete-orphan"
    )


class EmailUrl(Base):
    __tablename__ = "email_urls"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id"), nullable=False)
    raw_url: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="body_text")
    domain: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    email: Mapped[Email] = relationship(back_populates="urls")


class EmailAttachment(Base):
    __tablename__ = "email_attachments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id"), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False, default="unnamed")
    file_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False, default="application/octet-stream")
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    storage_note: Mapped[str] = mapped_column(Text, nullable=False, default="")

    email: Mapped[Email] = relationship(back_populates="attachments")


class DetectorResult(Base):
    __tablename__ = "detector_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id"), nullable=False)
    detector_name: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False, default="heuristic-v1")
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    email: Mapped[Email] = relationship(back_populates="detector_results")


class ConfidenceScore(Base):
    __tablename__ = "confidence_scores"

    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("emails.id"), primary_key=True
    )
    fused_risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_state: Mapped[str] = mapped_column(String(16), nullable=False)
    agreement_metric: Mapped[float] = mapped_column(Float, nullable=False)
    contributing_detectors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    fusion_method_version: Mapped[str] = mapped_column(String(64), nullable=False, default="weighted-v1")

    email: Mapped[Email] = relationship(back_populates="confidence")


class Decision(Base):
    __tablename__ = "decisions"

    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("emails.id"), primary_key=True
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    analyst_override: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    analyst_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    review_queue: Mapped[str | None] = mapped_column(String(32), nullable=True)

    email: Mapped[Email] = relationship(back_populates="decision")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    email_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    before_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    keys: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    dna_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    growth_rate_flag: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    emails: Mapped[list[Email]] = relationship(back_populates="campaign")


class FraudFingerprint(Base):
    __tablename__ = "fraud_fingerprints"

    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("emails.id"), primary_key=True
    )
    fuzzy_hash: Mapped[str] = mapped_column(String(32), nullable=False)
    embedding: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    embedding_version: Mapped[str] = mapped_column(String(64), nullable=False, default="hashing-char-v1")
    technique_tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    infrastructure_keys: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    nearest_email_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    similarity: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    email: Mapped[Email] = relationship(back_populates="fraud_dna")


class ComplaintCase(Base):
    __tablename__ = "complaint_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_ref: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("emails.id"), nullable=False, unique=True
    )
    victim_mobile: Mapped[str] = mapped_column(String(32), nullable=False, default="[MOBILE]")
    amount_lost: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    bank: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    incident_date: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    district: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    email: Mapped[Email] = relationship(back_populates="case")


class EvidenceVault(Base):
    __tablename__ = "evidence_vault"

    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("emails.id"), primary_key=True
    )
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    preserved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    email: Mapped[Email] = relationship(back_populates="vault")


class CustodyEvent(Base):
    __tablename__ = "custody_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("emails.id"), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    email: Mapped[Email] = relationship(back_populates="custody_events")


class UnlockRequest(Base):
    __tablename__ = "unlock_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("emails.id"), nullable=False, index=True
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    justification: Mapped[str] = mapped_column(Text, nullable=False, default="")
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    email: Mapped[Email] = relationship(back_populates="unlock_requests")


class DlpPolicy(Base):
    __tablename__ = "dlp_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    pattern: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False, default="quarantine")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, index=True
    )
