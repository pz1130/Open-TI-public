"""补充反查索引；告警按渠道记录送达，部分渠道失败时只重试失败的渠道

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMPTY_ARRAY = sa.text("'{}'::text[]")


def upgrade() -> None:
    # 每次处理都按 item_id 判断重放；开告警时按 finding_id 找旧告警。两个唯一约束/主键的首列都不是它们。
    op.create_index("ix_finding_observation_item_id", "finding_observation", ["item_id"])
    op.create_index("ix_alert_finding_finding_id", "alert_finding", ["finding_id"])
    op.create_index(
        "ix_domain_observation_watched_domain_id", "domain_observation", ["watched_domain_id"]
    )
    for col in ("notified_sinks", "digest_sinks"):
        op.add_column(
            "alert",
            sa.Column(col, pg.ARRAY(sa.Text()), server_default=EMPTY_ARRAY, nullable=False),
        )


def downgrade() -> None:
    op.drop_column("alert", "digest_sinks")
    op.drop_column("alert", "notified_sinks")
    op.drop_index("ix_domain_observation_watched_domain_id", "domain_observation")
    op.drop_index("ix_alert_finding_finding_id", "alert_finding")
    op.drop_index("ix_finding_observation_item_id", "finding_observation")
