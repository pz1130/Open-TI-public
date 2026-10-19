"""LLM providers (encrypted keys) and adjudication settings.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "llm_provider",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("preset", sa.Text(), nullable=False),
        sa.Column("base_url", sa.Text(), nullable=False),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("api_key_enc", sa.LargeBinary(), nullable=True),
        sa.Column("api_key_hint", sa.Text(), nullable=True),
        sa.Column("proxy_enc", sa.LargeBinary(), nullable=True),
        sa.Column("proxy_hint", sa.Text(), nullable=True),
        sa.Column("json_mode", sa.Boolean(), nullable=False),
        sa.Column("temperature", sa.Double(), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("last_test_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_test_ok", sa.Boolean(), nullable=True),
        sa.Column("last_test_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_llm_provider"),
        sa.UniqueConstraint("name", name="uq_llm_provider_name"),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["app_user.id"],
            name="fk_llm_provider_updated_by_app_user",
            ondelete="SET NULL",
        ),
    )
    op.create_table(
        "llm_settings",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("primary_id", sa.BigInteger(), nullable=True),
        sa.Column("backup_id", sa.BigInteger(), nullable=True),
        sa.Column("gray_zone_low", sa.Integer(), nullable=False),
        sa.Column("gray_zone_high", sa.Integer(), nullable=False),
        sa.Column("max_per_run", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("max_wait_minutes", sa.Integer(), nullable=False),
        sa.Column("summary_language", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_llm_settings"),
        sa.CheckConstraint("id = 1", name="ck_llm_settings_singleton"),
        sa.CheckConstraint(
            "primary_id IS NULL OR backup_id IS NULL OR primary_id <> backup_id",
            name="ck_llm_settings_distinct_providers",
        ),
        sa.CheckConstraint(
            "0 <= gray_zone_low AND gray_zone_low <= gray_zone_high AND gray_zone_high <= 100",
            name="ck_llm_settings_gray_zone",
        ),
        sa.ForeignKeyConstraint(
            ["primary_id"],
            ["llm_provider.id"],
            name="fk_llm_settings_primary_id_llm_provider",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["backup_id"],
            ["llm_provider.id"],
            name="fk_llm_settings_backup_id_llm_provider",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["app_user.id"],
            name="fk_llm_settings_updated_by_app_user",
            ondelete="SET NULL",
        ),
    )


def downgrade() -> None:
    op.drop_table("llm_settings")
    op.drop_table("llm_provider")
