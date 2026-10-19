"""Add certificate expiry monitors and discovered hosts.

Revision ID: 0028
Revises: 0027
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "certificate_monitor",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("project_id", sa.Text(), sa.ForeignKey("project.id"), nullable=False),
        sa.Column("root_domain", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("warn_days", sa.Integer(), server_default="30", nullable=False),
        sa.Column(
            "known_domains",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)),
        sa.Column("scan_started_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text()),
        sa.Column("truncated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.UniqueConstraint("project_id", "root_domain"),
    )
    op.create_index(
        "ix_certificate_monitor_next_check_at", "certificate_monitor", ["next_check_at"]
    )
    op.create_table(
        "monitored_certificate",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "monitor_id",
            sa.BigInteger(),
            sa.ForeignKey("certificate_monitor.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), server_default="unknown", nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True)),
        sa.Column("certificate_checked_at", sa.DateTime(timezone=True)),
        sa.Column("not_after", sa.DateTime(timezone=True)),
        sa.Column(
            "certificate", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("error", sa.Text()),
        sa.UniqueConstraint("monitor_id", "domain"),
    )


def downgrade() -> None:
    op.drop_table("monitored_certificate")
    op.drop_index("ix_certificate_monitor_next_check_at", table_name="certificate_monitor")
    op.drop_table("certificate_monitor")
