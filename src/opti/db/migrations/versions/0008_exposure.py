"""员工凭据暴露：受影响账户（S3-A）

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "exposed_account",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pushed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_exposed_account"),
        sa.ForeignKeyConstraint(
            ["project_id"], ["project.id"], name="fk_exposed_account_project_id_project"
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["finding.id"], name="fk_exposed_account_finding_id_finding"
        ),
        sa.UniqueConstraint("finding_id", "email", name="uq_exposed_account_finding_id"),
    )
    op.create_index("ix_exposed_account_last_seen", "exposed_account", ["last_seen"])


def downgrade() -> None:
    op.drop_table("exposed_account")
