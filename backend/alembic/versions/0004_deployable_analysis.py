"""deployable analysis timing and deep-path state

Revision ID: 0004_deployable
Revises: 0003_privacy
Create Date: 2026-10-01
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_deployable"
down_revision: Union[str, None] = "0003_privacy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "emails",
        sa.Column("analysis_mode", sa.String(length=16), nullable=False, server_default="adaptive"),
    )
    op.add_column("emails", sa.Column("fast_path_ms", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("emails", sa.Column("deep_path_ms", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("emails", sa.Column("total_analysis_ms", sa.Integer(), nullable=False, server_default="0"))
    op.add_column(
        "emails",
        sa.Column("deep_status", sa.String(length=16), nullable=False, server_default="complete"),
    )
    op.add_column(
        "emails",
        sa.Column(
            "models_run",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("emails", "models_run")
    op.drop_column("emails", "deep_status")
    op.drop_column("emails", "total_analysis_ms")
    op.drop_column("emails", "deep_path_ms")
    op.drop_column("emails", "fast_path_ms")
    op.drop_column("emails", "analysis_mode")
