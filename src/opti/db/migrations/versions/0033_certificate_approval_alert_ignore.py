"""Require certificate approval and retain ignored alerts with a semantic baseline.

Revision ID: 0033
Revises: 0032
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("alert", sa.Column("ignored_at", sa.DateTime(timezone=True)))
    op.add_column(
        "alert",
        sa.Column(
            "ignored_fingerprint",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column("monitored_certificate", sa.Column("approved_at", sa.DateTime(timezone=True)))
    op.add_column(
        "monitored_certificate",
        sa.Column("approved_by", sa.BigInteger(), sa.ForeignKey("app_user.id")),
    )
    op.add_column("monitored_certificate", sa.Column("warn_days", sa.Integer()))
    # 升级后所有主机待管理员确认，旧的未结提醒不再继续发送；保留历史记录。
    op.execute("""UPDATE alert SET status = 'closed', closed_at = now(), updated_at = now()
        WHERE status IN ('open', 'acknowledged') AND id IN (
            SELECT af.alert_id FROM alert_finding af JOIN finding f ON f.id = af.finding_id
            WHERE f.category = 'certificate_expiry')""")
    op.execute("""UPDATE finding SET match = match - 'certificate_alert_key'
        WHERE category = 'certificate_expiry'""")


def downgrade() -> None:
    op.drop_column("monitored_certificate", "warn_days")
    op.drop_column("monitored_certificate", "approved_by")
    op.drop_column("monitored_certificate", "approved_at")
    op.drop_column("alert", "ignored_fingerprint")
    op.drop_column("alert", "ignored_at")
