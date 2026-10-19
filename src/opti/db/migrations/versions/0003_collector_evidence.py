"""采集节点与证据（S1-D）

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-02
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMPTY_JSON = sa.text("'{}'::jsonb")


def _ts(name: str, *, nullable: bool = False) -> sa.Column[Any]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _text(name: str, *, nullable: bool = False) -> sa.Column[Any]:
    return sa.Column(name, sa.Text(), nullable=nullable)


def upgrade() -> None:
    op.add_column(
        "alert", sa.Column("evidence_status", sa.Text(), server_default="none", nullable=False)
    )
    op.add_column(
        "alert", sa.Column("evidence_attempts", sa.Integer(), server_default="0", nullable=False)
    )
    op.add_column("connector_run", _text("node_id", nullable=True))
    op.add_column("connector_run", _ts("deadline_at", nullable=True))
    op.create_table(
        "evidence",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("alert_id", sa.BigInteger(), nullable=True),
        _text("kind"),
        _text("object_key"),
        _text("sha256"),
        sa.Column("size", sa.BigInteger(), nullable=False),
        _text("content_type"),
        _text("version_id", nullable=True),
        _ts("captured_at"),
        _text("node_id"),
        _text("method"),
        _text("source_url", nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_evidence"),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["finding.id"], name="fk_evidence_finding_id_finding"
        ),
        sa.ForeignKeyConstraint(["alert_id"], ["alert.id"], name="fk_evidence_alert_id_alert"),
    )
    op.create_index("ix_evidence_finding_id", "evidence", ["finding_id"])
    op.create_table(
        "collector_node",
        _text("node_id"),
        _text("version"),
        _ts("last_seen"),
        sa.Column("status", pg.JSONB(), server_default=EMPTY_JSON, nullable=False),
        sa.PrimaryKeyConstraint("node_id", name="pk_collector_node"),
    )


def downgrade() -> None:
    op.drop_table("collector_node")
    op.drop_index("ix_evidence_finding_id", "evidence")
    op.drop_table("evidence")
    op.drop_column("connector_run", "deadline_at")
    op.drop_column("connector_run", "node_id")
    op.drop_column("alert", "evidence_attempts")
    op.drop_column("alert", "evidence_status")
