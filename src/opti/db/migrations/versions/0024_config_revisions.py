"""Web-managed configuration: versioned revisions and per-process load status.

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "config_revision",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("digest", sa.Text(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("restored_from", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_config_revision"),
        sa.UniqueConstraint("kind", "version", name="uq_config_revision_kind"),
        sa.CheckConstraint("kind IN ('rules', 'organization')", name="ck_config_revision_kind"),
        sa.CheckConstraint("version >= 1", name="ck_config_revision_version_positive"),
    )
    op.create_table(
        "config_runtime_status",
        sa.Column("process", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("digest", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("process", "kind", name="pk_config_runtime_status"),
    )


def downgrade() -> None:
    op.drop_table("config_runtime_status")
    op.drop_table("config_revision")
