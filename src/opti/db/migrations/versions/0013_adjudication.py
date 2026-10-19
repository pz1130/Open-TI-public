"""LLM adjudication queue and results (S4-D).

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "adjudication",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("held_severity", sa.Text(), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("leased_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("backend", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("prompt_version", sa.Text(), nullable=True),
        sa.Column("input_sha256", sa.Text(), nullable=True),
        sa.Column("verdict", sa.Text(), nullable=True),
        sa.Column("output", pg.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_adjudication"),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["finding.id"], name="fk_adjudication_finding_id_finding"
        ),
    )
    op.create_index("ix_adjudication_status_created_at", "adjudication", ["status", "created_at"])
    op.create_index("ix_adjudication_finding_id", "adjudication", ["finding_id"])


def downgrade() -> None:
    op.drop_table("adjudication")
