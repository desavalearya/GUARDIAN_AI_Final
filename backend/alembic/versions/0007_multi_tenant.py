"""organization tenancy boundaries

Revision ID: 0007_multi_tenant
Revises: 0006_fraud_dna
Create Date: 2026-10-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_multi_tenant"
down_revision: Union[str, None] = "0006_fraud_dna"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEFAULT_ORG = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("domains", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.execute(
        "INSERT INTO organizations (id, slug, name, domains) "
        f"VALUES ('{DEFAULT_ORG}', 'default', 'PhishProof Demo Organisation', '[\"example.com\", \"company-b.test\"]'::jsonb)"
    )
    for table in ("users", "emails", "campaigns", "dlp_policies"):
        op.add_column(
            table,
            sa.Column(
                "organization_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
                server_default=DEFAULT_ORG,
            ),
        )
        op.create_foreign_key(
            f"fk_{table}_organization_id",
            table,
            "organizations",
            ["organization_id"],
            ["id"],
        )
        op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])


def downgrade() -> None:
    for table in ("dlp_policies", "campaigns", "emails", "users"):
        op.drop_index(f"ix_{table}_organization_id", table_name=table)
        op.drop_constraint(f"fk_{table}_organization_id", table_name=table, type_="foreignkey")
        op.drop_column(table, "organization_id")
    op.drop_table("organizations")
