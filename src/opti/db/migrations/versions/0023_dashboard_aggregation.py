"""Dashboard aggregation: MTTD samples on finding and indexes for SQL statistics.

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "finding", sa.Column("first_alerted_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("finding", sa.Column("mttd_source", sa.Text(), nullable=True))
    op.add_column("finding", sa.Column("mttd_hours", sa.Double(), nullable=True))
    op.create_index(
        "ix_finding_project_id_first_alerted_at", "finding", ["project_id", "first_alerted_at"]
    )
    op.create_index("ix_finding_project_id_last_seen", "finding", ["project_id", "last_seen"])
    op.create_index("ix_alert_project_id_created_at", "alert", ["project_id", "created_at"])
    op.create_index("ix_alert_project_id_status", "alert", ["project_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_alert_project_id_status", table_name="alert")
    op.drop_index("ix_alert_project_id_created_at", table_name="alert")
    op.drop_index("ix_finding_project_id_last_seen", table_name="finding")
    op.drop_index("ix_finding_project_id_first_alerted_at", table_name="finding")
    op.drop_column("finding", "mttd_hours")
    op.drop_column("finding", "mttd_source")
    op.drop_column("finding", "first_alerted_at")
