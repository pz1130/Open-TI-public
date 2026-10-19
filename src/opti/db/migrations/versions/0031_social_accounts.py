"""Add protected social accounts and the similar accounts found for them.

Revision ID: 0031
Revises: 0030
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMPTY_ARRAY = sa.text("'{}'::text[]")


def upgrade() -> None:
    op.create_table(
        "protected_account",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("project_id", sa.Text(), sa.ForeignKey("project.id"), nullable=False),
        sa.Column("platform", sa.Text(), nullable=False),
        sa.Column("handle", sa.Text(), nullable=False),
        sa.Column("label", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "extra_queries", postgresql.ARRAY(sa.Text()), server_default=EMPTY_ARRAY, nullable=False
        ),
        sa.Column(
            "allowed_accounts",
            postgresql.ARRAY(sa.Text()),
            server_default=EMPTY_ARRAY,
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("platform_id", sa.Text()),
        sa.Column("display_name", sa.Text()),
        sa.Column("avatar_dhash", sa.Text()),
        sa.Column("avatar_sha256", sa.Text()),
        sa.Column("profile_checked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)),
        sa.Column("scan_started_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text()),
        sa.CheckConstraint(
            "platform IN ('bluesky', 'mastodon')", name="ck_protected_account_platform"
        ),
        sa.UniqueConstraint("project_id", "platform", "handle"),
    )
    op.create_index("ix_protected_account_next_check_at", "protected_account", ["next_check_at"])
    op.create_table(
        "account_candidate",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "protected_id",
            sa.BigInteger(),
            sa.ForeignKey("protected_account.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("platform_account_id", sa.Text(), nullable=False),
        sa.Column("handle", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), server_default="", nullable=False),
        sa.Column("profile_url", sa.Text(), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True)),
        sa.Column("bio", sa.Text(), server_default="", nullable=False),
        sa.Column("avatar_dhash", sa.Text()),
        sa.Column("avatar_sha256", sa.Text()),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column(
            "signals", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("finding_id", sa.BigInteger(), sa.ForeignKey("finding.id", ondelete="SET NULL")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("gone_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("protected_id", "platform_account_id"),
    )
    op.create_index("ix_account_candidate_last_seen", "account_candidate", ["last_seen"])


def downgrade() -> None:
    op.drop_index("ix_account_candidate_last_seen", table_name="account_candidate")
    op.drop_table("account_candidate")
    op.drop_index("ix_protected_account_next_check_at", table_name="protected_account")
    op.drop_table("protected_account")
