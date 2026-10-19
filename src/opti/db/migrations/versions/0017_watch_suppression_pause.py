"""Track watches paused by suppression so revocation and expiry can restore them.

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "watched_domain",
        sa.Column(
            "paused_by_suppression", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
    )
    # 恢复旧版本中由抑制规则暂停的监视项：只匹配暂停时间等于规则创建时间的行。
    op.execute(
        """
        UPDATE watched_domain AS wd SET paused_by_suppression = true, expires_at = NULL
        WHERE wd.expires_at IS NOT NULL AND EXISTS (
            SELECT 1 FROM suppression_rule AS sr
            WHERE sr.project_id = wd.project_id
              AND sr.created_at = wd.expires_at
              AND (
                (sr.kind = 'domain' AND sr.value = wd.domain)
                OR (sr.kind = 'registered_domain' AND (
                    sr.value = wd.domain
                    OR right(wd.domain, length(sr.value) + 1) = '.' || sr.value
                ))
              )
        )
        """
    )


def downgrade() -> None:
    op.drop_column("watched_domain", "paused_by_suppression")
