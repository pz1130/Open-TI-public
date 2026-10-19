"""Campaign view: grouped findings that share exclusive infrastructure.

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "campaign",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("note", sa.Text(), server_default="", nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("ignored", pg.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confirmed_by", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_campaign"),
        sa.ForeignKeyConstraint(
            ["project_id"], ["project.id"], name="fk_campaign_project_id_project"
        ),
        sa.ForeignKeyConstraint(
            ["confirmed_by"], ["app_user.id"], name="fk_campaign_confirmed_by_app_user"
        ),
    )
    op.create_index("ix_campaign_project_id_state", "campaign", ["project_id", "state"])
    op.create_index("ix_campaign_project_id_signature", "campaign", ["project_id", "signature"])
    op.create_table(
        "campaign_member",
        sa.Column("campaign_id", sa.BigInteger(), nullable=False),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("signals", pg.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.BigInteger(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("campaign_id", "finding_id", name="pk_campaign_member"),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaign.id"],
            name="fk_campaign_member_campaign_id_campaign",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["finding.id"], name="fk_campaign_member_finding_id_finding"
        ),
        sa.ForeignKeyConstraint(
            ["decided_by"], ["app_user.id"], name="fk_campaign_member_decided_by_app_user"
        ),
    )
    op.create_index("ix_campaign_member_finding_id", "campaign_member", ["finding_id"])


def downgrade() -> None:
    op.drop_table("campaign_member")
    op.drop_table("campaign")
