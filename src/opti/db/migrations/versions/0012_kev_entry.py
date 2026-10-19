"""CISA KEV entries (S4-C).

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "kev_entry",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), server_default="", nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("required_action", sa.Text(), server_default="", nullable=False),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("ransomware", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("notes", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "cwes", pg.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_kev_entry"),
        sa.UniqueConstraint("cve_id", name="uq_kev_entry_cve_id"),
    )
    op.create_index("ix_kev_entry_date_added", "kev_entry", ["date_added"])


def downgrade() -> None:
    op.drop_table("kev_entry")
