"""研判接口：账号、会话、审计日志、反馈、抑制规则（S1-E）

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-02
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EMPTY_JSON = sa.text("'{}'::jsonb")
EMPTY_ARRAY = sa.text("'{}'::text[]")


def _id() -> sa.Column[Any]:
    return sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False)


def _ts(name: str, *, nullable: bool = False) -> sa.Column[Any]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _text(name: str, *, nullable: bool = False, **kw: Any) -> sa.Column[Any]:
    return sa.Column(name, sa.Text(), nullable=nullable, **kw)


def _ref(name: str, *, nullable: bool = False) -> sa.Column[Any]:
    return sa.Column(name, sa.BigInteger(), nullable=nullable)


def _fk(table: str, col: str, ref: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint([col], [f"{ref}.id"], name=f"fk_{table}_{col}_{ref}")


def upgrade() -> None:
    op.create_table(
        "app_user",
        _id(),
        _text("username"),
        _text("display_name", server_default=""),
        _text("password_hash"),
        sa.Column("roles", pg.ARRAY(sa.Text()), server_default=EMPTY_ARRAY, nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("failed_logins", sa.Integer(), server_default="0", nullable=False),
        _ts("locked_until", nullable=True),
        _ts("created_at"),
        _ts("last_login_at", nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_app_user"),
        sa.UniqueConstraint("username", name="uq_app_user_username"),
    )
    op.create_table(
        "api_session",
        _text("id"),
        _ref("user_id"),
        _ts("created_at"),
        _ts("expires_at"),
        _ts("last_seen_at"),
        _text("ip", nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_api_session"),
        _fk("api_session", "user_id", "app_user"),
    )
    op.create_index("ix_api_session_user_id", "api_session", ["user_id"])
    op.create_table(
        "audit_log",
        _id(),
        _ts("ts"),
        _text("actor"),
        _text("action"),
        _text("target_type", nullable=True),
        _text("target_id", nullable=True),
        sa.Column("detail", pg.JSONB(), server_default=EMPTY_JSON, nullable=False),
        _text("ip", nullable=True),
        _text("request_id", nullable=True),
        _text("prev_hash"),
        _text("hash"),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
        sa.UniqueConstraint("hash", name="uq_audit_log_hash"),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    # 只追加（设计文档 11、16.3）：行级 UPDATE/DELETE 一律拒绝；TRUNCATE 属于 DBA 操作，不在此拦截
    op.execute(
        "CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $$ "
        "BEGIN RAISE EXCEPTION 'audit_log 只允许追加'; END $$ LANGUAGE plpgsql"
    )
    op.execute(
        "CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_log_append_only()"
    )
    op.create_table(
        "feedback",
        _id(),
        _ref("alert_id"),
        _ref("finding_id"),
        _ref("user_id"),
        _text("verdict"),
        _text("reason", server_default=""),
        _ts("created_at"),
        sa.PrimaryKeyConstraint("id", name="pk_feedback"),
        _fk("feedback", "alert_id", "alert"),
        _fk("feedback", "finding_id", "finding"),
        _fk("feedback", "user_id", "app_user"),
    )
    op.create_index("ix_feedback_alert_id", "feedback", ["alert_id"])
    op.create_table(
        "suppression_rule",
        _id(),
        _text("project_id"),
        _text("kind"),
        _text("value"),
        _text("reason", server_default=""),
        _ref("created_by", nullable=True),
        _ref("source_alert_id", nullable=True),
        _ts("created_at"),
        _ts("expires_at", nullable=True),
        _ts("revoked_at", nullable=True),
        _ref("revoked_by", nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_suppression_rule"),
        sa.ForeignKeyConstraint(
            ["project_id"], ["project.id"], name="fk_suppression_rule_project_id_project"
        ),
        _fk("suppression_rule", "created_by", "app_user"),
        _fk("suppression_rule", "source_alert_id", "alert"),
        _fk("suppression_rule", "revoked_by", "app_user"),
    )
    op.create_index(
        "ix_suppression_rule_project_id_value", "suppression_rule", ["project_id", "value"]
    )
    op.add_column("alert", _ref("assignee_id", nullable=True))
    op.create_foreign_key(
        "fk_alert_assignee_id_app_user", "alert", "app_user", ["assignee_id"], ["id"]
    )
    op.add_column("alert", _text("triage_verdict", nullable=True))
    op.add_column("alert", _ts("closed_at", nullable=True))
    op.add_column("alert", _ts("updated_at", nullable=True))


def downgrade() -> None:
    op.drop_column("alert", "updated_at")
    op.drop_column("alert", "closed_at")
    op.drop_column("alert", "triage_verdict")
    op.drop_constraint("fk_alert_assignee_id_app_user", "alert", type_="foreignkey")
    op.drop_column("alert", "assignee_id")
    op.drop_table("suppression_rule")
    op.drop_table("feedback")
    op.execute("DROP TRIGGER audit_log_append_only ON audit_log")
    op.execute("DROP FUNCTION audit_log_append_only()")
    op.drop_table("audit_log")
    op.drop_table("api_session")
    op.drop_table("app_user")
