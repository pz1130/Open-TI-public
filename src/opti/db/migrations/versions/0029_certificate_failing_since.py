"""Record since when a monitored host has failed, so long-dead hosts stop being checked.

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "monitored_certificate",
        sa.Column("failing_since", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("monitored_certificate", "failing_since")
