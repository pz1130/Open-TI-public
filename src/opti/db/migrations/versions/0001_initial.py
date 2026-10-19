"""初始数据模型（S1）

Revision ID: 0001
Revises:
Create Date: 2026-10-02
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMPTY_JSON = sa.text("'{}'::jsonb")
EMPTY_ARRAY = sa.text("'{}'::text[]")


def _id() -> sa.Column[Any]:
    return sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False)


def _ts(name: str, *, nullable: bool = False, **kw: Any) -> sa.Column[Any]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable, **kw)


def _text(name: str, *, nullable: bool = False, **kw: Any) -> sa.Column[Any]:
    return sa.Column(name, sa.Text(), nullable=nullable, **kw)


def _fk(col: str, table: str, ref: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint([col], [f"{ref}.id"], name=f"fk_{table}_{col}_{ref}")


def upgrade() -> None:
    op.create_table(
        "project",
        _text("id"),
        _text("tenant_id", server_default="default"),
        _text("name"),
        _text("authorization_ref"),
        _ts("created_at", server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_project"),
    )
    op.create_table(
        "raw_item",
        _text("item_id"),
        _ts("fetched_at"),
        _text("connector_id"),
        _text("source_item_id"),
        _text("url", nullable=True),
        sa.Column("payload", pg.JSONB(), nullable=False),
        sa.Column("project_ids", pg.ARRAY(sa.Text()), server_default=EMPTY_ARRAY, nullable=False),
        sa.PrimaryKeyConstraint("item_id", "fetched_at", name="pk_raw_item"),
        postgresql_partition_by="RANGE (fetched_at)",
    )
    # 兜底分区：防止尚未创建月分区时写入失败（月分区由每日任务提前创建）
    op.execute("CREATE TABLE raw_item_default PARTITION OF raw_item DEFAULT")
    op.create_table(
        "entity",
        _id(),
        _text("type"),
        _text("value"),
        _ts("first_seen"),
        _ts("last_seen"),
        sa.Column("enrichment", pg.JSONB(), server_default=EMPTY_JSON, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_entity"),
        sa.UniqueConstraint("type", "value", name="uq_entity_type"),
    )
    op.create_table(
        "finding",
        _id(),
        _text("project_id"),
        sa.Column("entity_id", sa.BigInteger(), nullable=False),
        _text("category"),
        sa.Column("score", sa.Integer(), nullable=False),
        _text("severity"),
        _text("status", server_default="new"),
        sa.Column("score_breakdown", pg.JSONB(), server_default=EMPTY_JSON, nullable=False),
        sa.Column("match", pg.JSONB(), server_default=EMPTY_JSON, nullable=False),
        sa.Column("sources", pg.ARRAY(sa.Text()), server_default=EMPTY_ARRAY, nullable=False),
        _ts("first_seen"),
        _ts("last_seen"),
        sa.PrimaryKeyConstraint("id", name="pk_finding"),
        _fk("project_id", "finding", "project"),
        _fk("entity_id", "finding", "entity"),
        sa.UniqueConstraint("project_id", "entity_id", name="uq_finding_project_id"),
    )
    op.create_table(
        "finding_observation",
        _id(),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        _text("item_id"),
        _text("connector_id"),
        _ts("observed_at"),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_finding_observation"),
        _fk("finding_id", "finding_observation", "finding"),
        sa.UniqueConstraint("finding_id", "item_id", name="uq_finding_observation_finding_id"),
    )
    op.create_table(
        "alert",
        _id(),
        _text("project_id"),
        _text("severity"),
        _text("status", server_default="open"),
        _ts("created_at"),
        _ts("notified_at", nullable=True),
        _ts("digest_sent_at", nullable=True),
        _text("ticket_ref", nullable=True),
        sa.Column("routing", pg.JSONB(), server_default=EMPTY_JSON, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_alert"),
        _fk("project_id", "alert", "project"),
    )
    op.create_index("ix_alert_status_severity", "alert", ["status", "severity"])
    op.create_table(
        "alert_finding",
        sa.Column("alert_id", sa.BigInteger(), nullable=False),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("alert_id", "finding_id", name="pk_alert_finding"),
        _fk("alert_id", "alert_finding", "alert"),
        _fk("finding_id", "alert_finding", "finding"),
    )
    op.create_table(
        "watched_domain",
        _id(),
        _text("project_id"),
        _text("domain"),
        _text("reason"),
        _text("state", server_default="unknown"),
        _ts("created_at"),
        _ts("next_check_at"),
        _ts("last_checked_at", nullable=True),
        sa.Column("last_fingerprint", pg.JSONB(), server_default=EMPTY_JSON, nullable=False),
        _ts("expires_at", nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_watched_domain"),
        _fk("project_id", "watched_domain", "project"),
        sa.UniqueConstraint("project_id", "domain", name="uq_watched_domain_project_id"),
    )
    op.create_index("ix_watched_domain_next_check_at", "watched_domain", ["next_check_at"])
    op.create_table(
        "domain_observation",
        _id(),
        sa.Column("watched_domain_id", sa.BigInteger(), nullable=False),
        _ts("observed_at"),
        _text("state"),
        sa.Column("fingerprint", pg.JSONB(), nullable=False),
        sa.Column("changes", pg.ARRAY(sa.Text()), nullable=False),
        sa.Column("data", pg.JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_domain_observation"),
        _fk("watched_domain_id", "domain_observation", "watched_domain"),
    )
    op.create_table(
        "connector_cursor",
        _text("connector_id"),
        _text("key"),
        _text("value"),
        _ts("updated_at"),
        sa.PrimaryKeyConstraint("connector_id", "key", name="pk_connector_cursor"),
    )
    op.create_table(
        "connector_run",
        _id(),
        _text("connector_id"),
        _ts("started_at"),
        _ts("ended_at", nullable=True),
        _text("status"),
        sa.Column("items", sa.Integer(), server_default="0", nullable=False),
        sa.Column("errors", sa.Integer(), server_default="0", nullable=False),
        _text("message", server_default=""),
        sa.PrimaryKeyConstraint("id", name="pk_connector_run"),
    )


def downgrade() -> None:
    for table in (
        "connector_run", "connector_cursor", "domain_observation", "watched_domain",
        "alert_finding", "alert", "finding_observation", "finding", "entity", "raw_item", "project",
    ):  # fmt: skip
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
