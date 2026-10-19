"""Public repository scan schedule (S3-C).

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "code_repo",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("repo", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("last_commit", sa.Text(), nullable=True),
        sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_code_repo"),
        sa.ForeignKeyConstraint(
            ["project_id"], ["project.id"], name="fk_code_repo_project_id_project"
        ),
        sa.UniqueConstraint("project_id", "repo", name="uq_code_repo_project_id"),
    )
    op.create_index("ix_code_repo_next_scan_at", "code_repo", ["next_scan_at"])


def downgrade() -> None:
    op.drop_table("code_repo")
