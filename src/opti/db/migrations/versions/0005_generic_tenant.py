"""租户默认值不再写死机构（S2-B）

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-02
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("project", "tenant_id", server_default="default")


def downgrade() -> None:
    op.alter_column("project", "tenant_id", server_default="default")
