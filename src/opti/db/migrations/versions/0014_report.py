"""Daily and weekly reports (S4-D).

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("language", sa.Text(), server_default="zh-CN", nullable=False),
        sa.Column("content", pg.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column(
            "sent_sinks",
            pg.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_report"),
        sa.ForeignKeyConstraint(
            ["project_id"], ["project.id"], name="fk_report_project_id_project"
        ),
        sa.UniqueConstraint("project_id", "kind", "period_end", name="uq_report_project_id"),
    )
    op.create_index("ix_report_created_at", "report", ["created_at"])


def downgrade() -> None:
    op.drop_table("report")
