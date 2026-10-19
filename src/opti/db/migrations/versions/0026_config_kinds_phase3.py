"""Allow phase 3 web-managed config kinds and their secrets.

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

REVISION_KINDS = (
    "'rules', 'organization', 'alerting', 'retention', 'campaigns', 'takedown', "
    "'takedown_templates', 'tickets', 'vendors', 'software', 'sharing'"
)
SECRET_KINDS = "'alerting', 'tickets', 'sharing'"


def _replace(table: str, values: str) -> None:
    name = f"ck_{table}_kind"
    op.drop_constraint(op.f(name), table, type_="check")
    op.create_check_constraint(op.f(name), table, f"kind IN ({values})")


def upgrade() -> None:
    _replace("config_revision", REVISION_KINDS)
    _replace("config_secret", SECRET_KINDS)


def downgrade() -> None:
    bind = op.get_bind()
    phase3_revisions = bind.execute(
        sa.text(
            "SELECT count(*) FROM config_revision WHERE kind NOT IN ('rules', 'organization', 'alerting')"
        )
    ).scalar()
    phase3_secrets = bind.execute(
        sa.text("SELECT count(*) FROM config_secret WHERE kind <> 'alerting'")
    ).scalar()
    if phase3_revisions or phase3_secrets:
        raise RuntimeError("第三期配置或密钥仍在使用，不能降级；请先迁移这些数据")
    _replace("config_revision", "'rules', 'organization', 'alerting'")
    _replace("config_secret", "'alerting'")
