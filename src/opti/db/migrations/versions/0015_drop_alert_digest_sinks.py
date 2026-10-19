"""Drop alert.digest_sinks: medium alerts are delivered inside daily reports (S4-D).

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("alert", "digest_sinks")


def downgrade() -> None:
    op.add_column(
        "alert",
        sa.Column(
            "digest_sinks",
            pg.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
    )
