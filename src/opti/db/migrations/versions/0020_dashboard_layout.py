"""Customizable dashboard: per-user layouts and one organization default.

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dashboard_layout",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.Column("layout", pg.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_dashboard_layout"),
        sa.UniqueConstraint("user_id", name="uq_dashboard_layout_user_id"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.id"],
            name="fk_dashboard_layout_user_id_app_user",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["app_user.id"],
            name="fk_dashboard_layout_updated_by_app_user",
            ondelete="SET NULL",
        ),
    )
    # 机构默认（user_id 为空）只能有一行；普通唯一约束不限制多个 NULL
    op.execute(
        "CREATE UNIQUE INDEX uq_dashboard_layout_default ON dashboard_layout ((user_id IS NULL))"
        " WHERE user_id IS NULL"
    )


def downgrade() -> None:
    op.drop_table("dashboard_layout")
