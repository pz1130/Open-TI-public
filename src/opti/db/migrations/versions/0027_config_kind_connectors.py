"""Allow web-managed connector settings and credentials.

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PHASE3_KINDS = (
    "'rules', 'organization', 'alerting', 'retention', 'campaigns', 'takedown', "
    "'takedown_templates', 'tickets', 'vendors', 'software', 'sharing'"
)
PHASE3_SECRETS = "'alerting', 'tickets', 'sharing'"


def _replace(table: str, values: str) -> None:
    name = f"ck_{table}_kind"
    op.drop_constraint(op.f(name), table, type_="check")
    op.create_check_constraint(op.f(name), table, f"kind IN ({values})")


def upgrade() -> None:
    _replace("config_revision", f"{PHASE3_KINDS}, 'connectors'")
    _replace("config_secret", f"{PHASE3_SECRETS}, 'connectors'")


def downgrade() -> None:
    bind = op.get_bind()
    used = bind.execute(
        sa.text(
            "SELECT (SELECT count(*) FROM config_revision WHERE kind = 'connectors')"
            " + (SELECT count(*) FROM config_secret WHERE kind = 'connectors')"
        )
    ).scalar()
    if used:
        raise RuntimeError("连接器网页设置仍在数据库中，不能降级；请先迁移这些数据")
    _replace("config_revision", PHASE3_KINDS)
    _replace("config_secret", PHASE3_SECRETS)
