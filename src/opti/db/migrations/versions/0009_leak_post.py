"""Ransomware aggregator posts (S3-B).

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "leak_post",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("group_name", sa.Text(), nullable=False),
        sa.Column("victim", sa.Text(), nullable=False),
        sa.Column("domain", sa.Text(), nullable=True),
        sa.Column("country", sa.Text(), nullable=True),
        sa.Column("activity", sa.Text(), nullable=True),
        sa.Column("discovered", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "sources", pg.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False
        ),
        sa.Column(
            "links", pg.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False
        ),
        sa.Column(
            "other_links",
            pg.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_leak_post"),
        sa.UniqueConstraint("key", name="uq_leak_post_key"),
    )
    op.create_index("ix_leak_post_discovered", "leak_post", ["discovered"])


def downgrade() -> None:
    op.drop_table("leak_post")
