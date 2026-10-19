"""单点登录：账号来源与身份、会话登录方式、进行中的登录（S2-D）

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "app_user", sa.Column("auth_source", sa.Text(), server_default="local", nullable=False)
    )
    op.add_column("app_user", sa.Column("oidc_issuer", sa.Text(), nullable=True))
    op.add_column("app_user", sa.Column("oidc_subject", sa.Text(), nullable=True))
    op.add_column("app_user", sa.Column("email", sa.Text(), nullable=True))
    op.create_unique_constraint(
        "uq_app_user_oidc_issuer", "app_user", ["oidc_issuer", "oidc_subject"]
    )
    op.add_column(
        "api_session",
        sa.Column("auth_method", sa.Text(), server_default="password", nullable=False),
    )
    op.create_table(
        "oidc_login",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("binding_hash", sa.Text(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=False),
        sa.Column("code_verifier", sa.Text(), nullable=False),
        sa.Column("next_path", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_oidc_login"),
    )
    op.create_index("ix_oidc_login_expires_at", "oidc_login", ["expires_at"])


def downgrade() -> None:
    op.drop_table("oidc_login")
    op.drop_column("api_session", "auth_method")
    op.drop_constraint("uq_app_user_oidc_issuer", "app_user", type_="unique")
    op.drop_column("app_user", "email")
    op.drop_column("app_user", "oidc_subject")
    op.drop_column("app_user", "oidc_issuer")
    op.drop_column("app_user", "auth_source")
