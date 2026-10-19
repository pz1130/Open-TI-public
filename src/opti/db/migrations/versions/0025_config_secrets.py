"""Web-managed configuration secrets; allow the alerting config kind.

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "config_secret",
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("value_enc", sa.LargeBinary(), nullable=True),
        sa.Column("hint", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("kind", "name", name="pk_config_secret"),
        # op.f：命名约定含 constraint_name，裸名字会被再加一层前缀。
        sa.CheckConstraint("kind IN ('alerting')", name=op.f("ck_config_secret_kind")),
    )
    # 0024 写了已渲染的名字且未包 op.f()，库里的名字被约定加长了一次。
    op.drop_constraint(
        op.f("ck_config_revision_ck_config_revision_kind"), "config_revision", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_config_revision_kind"), "config_revision",
        "kind IN ('rules', 'organization', 'alerting')",
    )  # fmt: skip


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(
        sa.text("SELECT count(*) FROM config_revision WHERE kind = 'alerting'")
    ).scalar():
        raise RuntimeError("config_revision 中已有 alerting 版本，不能降级；请先删除这些行")
    op.drop_table("config_secret")
    op.drop_constraint(op.f("ck_config_revision_kind"), "config_revision", type_="check")
    op.create_check_constraint(
        op.f("ck_config_revision_ck_config_revision_kind"),
        "config_revision",
        "kind IN ('rules', 'organization')",
    )
