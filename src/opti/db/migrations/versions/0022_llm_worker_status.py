"""LLM settings: the adjudication worker reports what it sees each run.

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "llm_settings", sa.Column("worker_checked_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("llm_settings", sa.Column("worker_problem", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("llm_settings", "worker_problem")
    op.drop_column("llm_settings", "worker_checked_at")
