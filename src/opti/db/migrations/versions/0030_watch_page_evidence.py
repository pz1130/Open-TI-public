"""Attach screenshots and HTML evidence directly to watchlist observations.

Revision ID: 0030
Revises: 0029
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("evidence", "finding_id", existing_type=sa.BigInteger(), nullable=True)
    op.add_column("evidence", sa.Column("watch_observation_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        op.f("fk_evidence_watch_observation_id_domain_observation"),
        "evidence",
        "domain_observation",
        ["watch_observation_id"],
        ["id"],
    )
    op.create_index("ix_evidence_watch_observation_id", "evidence", ["watch_observation_id"])
    op.create_check_constraint(
        op.f("ck_evidence_one_parent"),
        "evidence",
        "(finding_id IS NOT NULL) <> (watch_observation_id IS NOT NULL)",
    )


def downgrade() -> None:
    if (
        op.get_bind()
        .execute(sa.text("SELECT count(*) FROM evidence WHERE watch_observation_id IS NOT NULL"))
        .scalar()
    ):
        raise RuntimeError("监视列表仍有网页证据，不能降级；请先迁移这些证据")
    op.drop_constraint(op.f("ck_evidence_one_parent"), "evidence", type_="check")
    op.drop_index("ix_evidence_watch_observation_id", table_name="evidence")
    op.drop_constraint(
        op.f("fk_evidence_watch_observation_id_domain_observation"), "evidence", type_="foreignkey"
    )
    op.drop_column("evidence", "watch_observation_id")
    op.alter_column("evidence", "finding_id", existing_type=sa.BigInteger(), nullable=False)
