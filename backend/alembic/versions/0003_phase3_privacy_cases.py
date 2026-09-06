"""privacy vault, campaigns, cases, custody

Revision ID: 0003_privacy
Revises: 0002_phase2
Create Date: 2026-09-06
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_privacy"
down_revision: Union[str, None] = "0002_phase2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("keys", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column("emails", sa.Column("evidence_sha256", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("emails", sa.Column("secret_flags", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.add_column("emails", sa.Column("hmac_tokens", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")))
    op.add_column("emails", sa.Column("retention_days", sa.Integer(), nullable=False, server_default="30"))
    op.add_column("emails", sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_emails_campaign_id", "emails", "campaigns", ["campaign_id"], ["id"])
    op.create_table(
        "complaint_cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("case_ref", sa.String(length=64), nullable=False),
        sa.Column("email_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("victim_mobile", sa.String(length=32), nullable=False),
        sa.Column("amount_lost", sa.String(length=64), nullable=False),
        sa.Column("bank", sa.String(length=128), nullable=False),
        sa.Column("incident_date", sa.String(length=32), nullable=False),
        sa.Column("district", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_ref"),
        sa.UniqueConstraint("email_id"),
    )
    op.create_table(
        "evidence_vault",
        sa.Column("email_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("preserved", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
        sa.PrimaryKeyConstraint("email_id"),
    )
    op.create_table(
        "custody_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("custody_events")
    op.drop_table("evidence_vault")
    op.drop_table("complaint_cases")
    op.drop_constraint("fk_emails_campaign_id", "emails", type_="foreignkey")
    op.drop_column("emails", "campaign_id")
    op.drop_column("emails", "retention_days")
    op.drop_column("emails", "hmac_tokens")
    op.drop_column("emails", "secret_flags")
    op.drop_column("emails", "evidence_sha256")
    op.drop_table("campaigns")
