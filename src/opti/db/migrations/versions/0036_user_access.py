"""Web user management, custom roles and permission sets.

Revision ID: 0036
Revises: 0035
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0036"
down_revision: str | None = "0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for name in ("assigned_roles", "permission_sets"):
        op.add_column(
            "app_user",
            sa.Column(
                name,
                postgresql.ARRAY(sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::text[]"),
            ),
        )
    op.add_column(
        "app_user",
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "app_user", sa.Column("access_version", sa.Integer(), nullable=False, server_default="1")
    )
    for table, field in (("access_role", "permission_sets"), ("permission_set", "permissions")):
        op.create_table(
            table,
            sa.Column("name", sa.Text(), primary_key=True),
            sa.Column("display_name", sa.Text(), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column(
                field,
                postgresql.ARRAY(sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::text[]"),
            ),
            sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        )


def downgrade() -> None:
    op.drop_table("access_role")
    op.drop_table("permission_set")
    for name in ("access_version", "must_change_password", "permission_sets", "assigned_roles"):
        op.drop_column("app_user", name)
