"""Allow identity and business operation settings managed by administrators.

Revision ID: 0032
Revises: 0031
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_REVISIONS = (
    "'rules', 'organization', 'alerting', 'retention', 'campaigns', 'takedown', "
    "'takedown_templates', 'tickets', 'vendors', 'software', 'sharing', 'connectors'"
)
OLD_SECRETS = "'alerting', 'tickets', 'sharing', 'connectors'"


def _replace(table: str, values: str) -> None:
    name = f"ck_{table}_kind"
    op.drop_constraint(op.f(name), table, type_="check")
    op.create_check_constraint(op.f(name), table, f"kind IN ({values})")


def upgrade() -> None:
    _replace("config_revision", f"{OLD_REVISIONS}, 'identity', 'operations'")
    _replace("config_secret", f"{OLD_SECRETS}, 'identity'")


def downgrade() -> None:
    used = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT (SELECT count(*) FROM config_revision WHERE kind IN ('identity', 'operations'))"
                " + (SELECT count(*) FROM config_secret WHERE kind = 'identity')"
            )
        )
        .scalar()
    )
    if used:
        raise RuntimeError("登录或业务设置仍在数据库中，不能降级；请先迁移这些数据")
    op.execute("DELETE FROM config_runtime_status WHERE kind IN ('identity', 'operations')")
    _replace("config_revision", OLD_REVISIONS)
    _replace("config_secret", OLD_SECRETS)
