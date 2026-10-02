"""fraud DNA fingerprints and campaign graph metadata

Revision ID: 0006_fraud_dna
Revises: 0005_enterprise
Create Date: 2026-10-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_fraud_dna"
down_revision: Union[str, None] = "0005_enterprise"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "campaigns",
        sa.Column("dna_summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "campaigns",
        sa.Column("growth_rate_flag", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_table(
        "fraud_fingerprints",
        sa.Column("email_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fuzzy_hash", sa.String(length=32), nullable=False),
        sa.Column("embedding", postgresql.JSONB(), nullable=False),
        sa.Column("embedding_version", sa.String(length=64), nullable=False),
        sa.Column("technique_tags", postgresql.JSONB(), nullable=False),
        sa.Column("infrastructure_keys", postgresql.JSONB(), nullable=False),
        sa.Column("nearest_email_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("similarity", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
        sa.PrimaryKeyConstraint("email_id"),
    )


def downgrade() -> None:
    op.drop_table("fraud_fingerprints")
    op.drop_column("campaigns", "growth_rate_flag")
    op.drop_column("campaigns", "dna_summary")
