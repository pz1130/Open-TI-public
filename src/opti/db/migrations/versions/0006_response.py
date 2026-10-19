"""处置闭环：下架投诉、投诉事件、API Token、告警工单字段（S2-C）

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-03
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMPTY_ARRAY = sa.text("'{}'::text[]")


def _id() -> sa.Column[Any]:
    return sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False)


def _ts(name: str, *, nullable: bool = False) -> sa.Column[Any]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _text(name: str, *, nullable: bool = False, **kw: Any) -> sa.Column[Any]:
    return sa.Column(name, sa.Text(), nullable=nullable, **kw)


def _ref(name: str, *, nullable: bool = False) -> sa.Column[Any]:
    return sa.Column(name, sa.BigInteger(), nullable=nullable)


def _fk(table: str, col: str, ref: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint([col], [f"{ref}.id"], name=f"fk_{table}_{col}_{ref}")


def upgrade() -> None:
    op.add_column("alert", _ts("ticket_pushed_at", nullable=True))
    op.add_column("alert", _text("ticket_status", nullable=True))
    op.add_column("alert", _ts("ticket_synced_at", nullable=True))
    op.create_table(
        "takedown",
        _id(),
        _text("project_id"),
        _ref("alert_id"),
        _ref("finding_id"),
        _text("domain"),
        sa.Column("target", pg.JSONB(), nullable=False),
        _text("language"),
        _text("subject"),
        _text("body"),
        _text("state", server_default="draft"),
        _ref("created_by"),
        _ref("approved_by", nullable=True),
        _text("external_ref", nullable=True),
        _ts("created_at"),
        _ts("updated_at"),
        _ts("approved_at", nullable=True),
        _ts("submitted_at", nullable=True),
        _ts("acknowledged_at", nullable=True),
        _ts("resolved_at", nullable=True),
        _ts("due_at", nullable=True),
        sa.Column("reminders", sa.Integer(), server_default="0", nullable=False),
        _ref("reappeared_alert_id", nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_takedown"),
        sa.ForeignKeyConstraint(
            ["project_id"], ["project.id"], name="fk_takedown_project_id_project"
        ),
        _fk("takedown", "alert_id", "alert"),
        _fk("takedown", "finding_id", "finding"),
        _fk("takedown", "created_by", "app_user"),
        _fk("takedown", "approved_by", "app_user"),
        _fk("takedown", "reappeared_alert_id", "alert"),
    )
    op.create_index("ix_takedown_alert_id", "takedown", ["alert_id"])
    op.create_index("ix_takedown_state", "takedown", ["state"])
    op.create_index("ix_takedown_project_id_domain", "takedown", ["project_id", "domain"])
    op.create_table(
        "takedown_event",
        _id(),
        _ref("takedown_id"),
        _ts("ts"),
        _text("actor"),
        _text("from_state", nullable=True),
        _text("to_state"),
        _text("note", server_default=""),
        sa.PrimaryKeyConstraint("id", name="pk_takedown_event"),
        _fk("takedown_event", "takedown_id", "takedown"),
    )
    op.create_index("ix_takedown_event_takedown_id", "takedown_event", ["takedown_id"])
    op.create_table(
        "api_token",
        _id(),
        _text("name"),
        _text("token_hash"),
        _text("prefix"),
        sa.Column("scopes", pg.ARRAY(sa.Text()), server_default=EMPTY_ARRAY, nullable=False),
        _text("created_by"),
        _ts("created_at"),
        _ts("expires_at"),
        _ts("last_used_at", nullable=True),
        _ts("revoked_at", nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_api_token"),
        sa.UniqueConstraint("name", name="uq_api_token_name"),
        sa.UniqueConstraint("token_hash", name="uq_api_token_token_hash"),
    )


def downgrade() -> None:
    op.drop_table("api_token")
    op.drop_table("takedown_event")
    op.drop_table("takedown")
    op.drop_column("alert", "ticket_synced_at")
    op.drop_column("alert", "ticket_status")
    op.drop_column("alert", "ticket_pushed_at")
