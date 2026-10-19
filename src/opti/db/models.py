"""PostgreSQL 数据模型（设计文档 6.2 的 S1 子集）。

v0.2 实现取舍：Finding 以"项目 + 实体"为唯一键（设计文档 10.3）；
官方资产与已知合法相似方暂存于 keywords.yaml；审计日志、反馈、抑制规则随 S1-E 的 API 一起实现。
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, ClassVar

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Double,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
EMPTY_JSON = text("'{}'::jsonb")
EMPTY_ARRAY = text("'{}'::text[]")


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map: ClassVar[dict[Any, Any]] = {
        str: Text(),
        datetime: DateTime(timezone=True),
        dict[str, Any]: JSONB(),
        list[str]: ARRAY(Text()),
    }


class Project(Base):
    __tablename__ = "project"

    id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(server_default="default")
    name: Mapped[str]
    authorization_ref: Mapped[str]
    rules_yaml: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class RawItemRow(Base):
    __tablename__ = "raw_item"
    # 单元素元组：末项字典是 Table 关键字参数，避免类属性上的可变字面量（RUF012）。
    __table_args__ = ({"postgresql_partition_by": "RANGE (fetched_at)"},)

    item_id: Mapped[str] = mapped_column(primary_key=True)
    fetched_at: Mapped[datetime] = mapped_column(primary_key=True)
    connector_id: Mapped[str]
    source_item_id: Mapped[str]
    url: Mapped[str | None]
    payload: Mapped[dict[str, Any]]
    project_ids: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)


class Entity(Base):
    __tablename__ = "entity"
    __table_args__ = (UniqueConstraint("type", "value"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    type: Mapped[str]
    value: Mapped[str]
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    # {富化器 id: {"data": {...}, "fetched_at": ISO 时间}}
    enrichment: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)


class Finding(Base):
    __tablename__ = "finding"
    __table_args__ = (
        UniqueConstraint("project_id", "entity_id"),
        Index("ix_finding_project_id_first_alerted_at", "project_id", "first_alerted_at"),
        Index("ix_finding_project_id_last_seen", "project_id", "last_seen"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    entity_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("entity.id"))
    category: Mapped[str]
    score: Mapped[int]
    severity: Mapped[str]
    status: Mapped[str] = mapped_column(server_default="new")
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    match: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    sources: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    # MTTD 样本（设计 2026-10-11）：第一条告警打开时算出并固定；来源不计或缺起点时间则 source/hours 为空
    first_alerted_at: Mapped[datetime | None]
    mttd_source: Mapped[str | None]
    mttd_hours: Mapped[float | None] = mapped_column(Double)


class FindingObservation(Base):
    __tablename__ = "finding_observation"
    __table_args__ = (
        UniqueConstraint("finding_id", "item_id"),
        Index("ix_finding_observation_item_id", "item_id"),  # 重放判断按 item_id 查
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("finding.id"))
    item_id: Mapped[str]
    connector_id: Mapped[str]
    observed_at: Mapped[datetime]
    score: Mapped[int]


class Alert(Base):
    __tablename__ = "alert"
    __table_args__ = (
        Index("ix_alert_status_severity", "status", "severity"),
        Index("ix_alert_project_id_created_at", "project_id", "created_at"),
        Index("ix_alert_project_id_status", "project_id", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    severity: Mapped[str]
    # open / superseded / acknowledged / closed
    status: Mapped[str] = mapped_column(server_default="open")
    created_at: Mapped[datetime]
    notified_at: Mapped[datetime | None]
    digest_sent_at: Mapped[datetime | None]
    siem_sinks: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    siem_sent_at: Mapped[datetime | None]
    ticket_ref: Mapped[str | None]
    # 工单（设计文档 12、D8）：ticket_ref 为工单系统编号（S1 已有列）
    ticket_pushed_at: Mapped[datetime | None]
    ticket_status: Mapped[str | None]  # 工单系统回调报告的原始状态
    ticket_synced_at: Mapped[
        datetime | None
    ]  # 最近一次已应用回调的签名时间；更早或相同的回调视为重放
    routing: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    # 已送达的渠道名。全部渠道送达才盖 notified_at；digest_sent_at 表示已收入日报。
    notified_sinks: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)

    # 取证状态：none（不需要）/ pending / done / failed（设计文档 3.3 证据优先）
    evidence_status: Mapped[str] = mapped_column(server_default="none")
    evidence_attempts: Mapped[int] = mapped_column(server_default="0")

    assignee_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    # 研判结论（设计文档 9.3）：true_positive / false_positive / duplicate / benign_known / out_of_scope
    triage_verdict: Mapped[str | None]
    closed_at: Mapped[datetime | None]
    updated_at: Mapped[datetime | None]

    ignored_at: Mapped[datetime | None]
    ignored_fingerprint: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)


class AlertFinding(Base):
    __tablename__ = "alert_finding"
    __table_args__ = (Index("ix_alert_finding_finding_id", "finding_id"),)

    alert_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("alert.id"), primary_key=True)
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("finding.id"), primary_key=True)


class WatchedDomain(Base):
    __tablename__ = "watched_domain"
    __table_args__ = (
        UniqueConstraint("project_id", "domain"),
        Index("ix_watched_domain_next_check_at", "next_check_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    domain: Mapped[str]
    reason: Mapped[str]
    state: Mapped[str] = mapped_column(server_default="unknown")
    created_at: Mapped[datetime]
    next_check_at: Mapped[datetime]
    last_checked_at: Mapped[datetime | None]
    last_fingerprint: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    expires_at: Mapped[datetime | None]
    paused_by_suppression: Mapped[bool] = mapped_column(server_default=text("false"))


class CertificateMonitor(Base):
    __tablename__ = "certificate_monitor"
    __table_args__ = (
        UniqueConstraint("project_id", "root_domain"),
        Index("ix_certificate_monitor_next_check_at", "next_check_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    root_domain: Mapped[str]
    enabled: Mapped[bool] = mapped_column(server_default=text("true"))
    warn_days: Mapped[int] = mapped_column(server_default="30")
    known_domains: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    created_at: Mapped[datetime]
    next_check_at: Mapped[datetime]
    last_checked_at: Mapped[datetime | None]
    scan_started_at: Mapped[datetime | None]
    error: Mapped[str | None]
    truncated: Mapped[bool] = mapped_column(server_default=text("false"))


class MonitoredCertificate(Base):
    __tablename__ = "monitored_certificate"
    __table_args__ = (UniqueConstraint("monitor_id", "domain"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    monitor_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("certificate_monitor.id", ondelete="CASCADE")
    )
    domain: Mapped[str]
    state: Mapped[str] = mapped_column(server_default="unknown")
    checked_at: Mapped[datetime | None]
    certificate_checked_at: Mapped[datetime | None]
    not_after: Mapped[datetime | None]
    certificate: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    error: Mapped[str | None]
    failing_since: Mapped[datetime | None]  # 连续读取失败的起点；成功即清空
    approved_at: Mapped[datetime | None]
    approved_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    warn_days: Mapped[int | None]  # 空值继承根域名配置


class ProtectedAccount(Base):
    """管理员登记的受保护社交账号；platform_id 起的字段每次检查时从平台刷新。"""

    __tablename__ = "protected_account"
    __table_args__ = (
        UniqueConstraint("project_id", "platform", "handle"),
        CheckConstraint("platform IN ('bluesky', 'mastodon')", name="platform"),
        Index("ix_protected_account_next_check_at", "next_check_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    platform: Mapped[str]
    handle: Mapped[str]
    label: Mapped[str] = mapped_column(server_default="")
    extra_queries: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    allowed_accounts: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    enabled: Mapped[bool] = mapped_column(server_default=text("true"))
    platform_id: Mapped[str | None]
    display_name: Mapped[str | None]
    avatar_dhash: Mapped[str | None]
    avatar_sha256: Mapped[str | None]
    profile_checked_at: Mapped[datetime | None]
    created_at: Mapped[datetime]
    next_check_at: Mapped[datetime]
    last_checked_at: Mapped[datetime | None]
    scan_started_at: Mapped[datetime | None]
    error: Mapped[str | None]


class AccountCandidate(Base):
    """搜到的相似账号：只保存判定所需的资料，按平台永久 ID 去重。"""

    __tablename__ = "account_candidate"
    __table_args__ = (
        UniqueConstraint("protected_id", "platform_account_id"),
        Index("ix_account_candidate_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    protected_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("protected_account.id", ondelete="CASCADE")
    )
    platform_account_id: Mapped[str]
    handle: Mapped[str]
    display_name: Mapped[str] = mapped_column(server_default="")
    profile_url: Mapped[str]
    registered_at: Mapped[datetime | None]
    bio: Mapped[str] = mapped_column(server_default="")
    avatar_dhash: Mapped[str | None]
    avatar_sha256: Mapped[str | None]
    score: Mapped[int]
    signals: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    finding_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("finding.id", ondelete="SET NULL")
    )
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    gone_at: Mapped[datetime | None]


class DomainObservation(Base):
    __tablename__ = "domain_observation"
    __table_args__ = (Index("ix_domain_observation_watched_domain_id", "watched_domain_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    watched_domain_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("watched_domain.id"))
    observed_at: Mapped[datetime]
    state: Mapped[str]
    fingerprint: Mapped[dict[str, Any]]
    changes: Mapped[list[str]]
    data: Mapped[dict[str, Any]]


class ConnectorCursor(Base):
    __tablename__ = "connector_cursor"

    connector_id: Mapped[str] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[str]
    updated_at: Mapped[datetime]


class ConnectorRun(Base):
    __tablename__ = "connector_run"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    connector_id: Mapped[str]
    started_at: Mapped[datetime]
    ended_at: Mapped[datetime | None]
    status: Mapped[str]
    items: Mapped[int] = mapped_column(server_default="0")
    errors: Mapped[int] = mapped_column(server_default="0")
    message: Mapped[str] = mapped_column(server_default="")

    node_id: Mapped[str | None]  # 下发到采集节点执行时的节点 ID
    deadline_at: Mapped[datetime | None]  # 超过此时间仍未回报则判为失败


class Evidence(Base):
    """证据链（设计文档 11）：对象存储中的截图与 HTML 快照，带哈希、采集时间、方法与节点。"""

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_finding_id", "finding_id"),
        Index("ix_evidence_watch_observation_id", "watch_observation_id"),
        CheckConstraint(
            "(finding_id IS NOT NULL) <> (watch_observation_id IS NOT NULL)", name="one_parent"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("finding.id"))
    watch_observation_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("domain_observation.id")
    )
    alert_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("alert.id"))
    kind: Mapped[str]  # screenshot / html / upload
    object_key: Mapped[str]
    sha256: Mapped[str]
    size: Mapped[int] = mapped_column(BigInteger)
    content_type: Mapped[str]
    version_id: Mapped[str | None]
    captured_at: Mapped[datetime]
    node_id: Mapped[str]
    method: Mapped[str]  # 工具与版本，如 "opti-sandbox/0.1.0 (chromium 140.0)"
    source_url: Mapped[str | None]
    uploaded_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    original_sha256: Mapped[str | None]


class CollectorNode(Base):
    __tablename__ = "collector_node"

    node_id: Mapped[str] = mapped_column(primary_key=True)
    version: Mapped[str]
    last_seen: Mapped[datetime]
    status: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)


class AppUser(Base):
    """本地账号（S1）；S2 接入 OIDC 后保留作为映射与应急账号。user 是保留字，改名 app_user。"""

    __tablename__ = "app_user"
    __table_args__ = (UniqueConstraint("username"), UniqueConstraint("oidc_issuer", "oidc_subject"))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    username: Mapped[str]
    display_name: Mapped[str] = mapped_column(server_default="")
    password_hash: Mapped[str]
    roles: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    active: Mapped[bool] = mapped_column(server_default=text("true"))
    failed_logins: Mapped[int] = mapped_column(server_default="0")
    locked_until: Mapped[datetime | None]
    created_at: Mapped[datetime]
    last_login_at: Mapped[datetime | None]
    # 账号来源：local（本地口令，S1 / 应急）或 oidc（单点登录自动建档，没有可用口令）
    auth_source: Mapped[str] = mapped_column(server_default="local")
    oidc_issuer: Mapped[str | None]
    oidc_subject: Mapped[str | None]
    email: Mapped[str | None]
    assigned_roles: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    permission_sets: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    must_change_password: Mapped[bool] = mapped_column(server_default=text("false"))
    access_version: Mapped[int] = mapped_column(server_default="1")


class AccessRole(Base):
    __tablename__ = "access_role"

    name: Mapped[str] = mapped_column(primary_key=True)
    display_name: Mapped[str]
    description: Mapped[str] = mapped_column(server_default="")
    permission_sets: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    version: Mapped[int] = mapped_column(server_default="1")


class PermissionSet(Base):
    __tablename__ = "permission_set"

    name: Mapped[str] = mapped_column(primary_key=True)
    display_name: Mapped[str]
    description: Mapped[str] = mapped_column(server_default="")
    permissions: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    version: Mapped[int] = mapped_column(server_default="1")


class ApiSession(Base):
    __tablename__ = "api_session"
    __table_args__ = (Index("ix_api_session_user_id", "user_id"),)

    id: Mapped[str] = mapped_column(primary_key=True)  # 会话令牌的 SHA-256；令牌本身不入库
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    ip: Mapped[str | None]
    auth_method: Mapped[str] = mapped_column(server_default="password")  # password / oidc


class AuditLog(Base):
    """审计日志（设计文档 16.3）：只追加（触发器禁止 UPDATE/DELETE），每条记录带前一条的哈希。"""

    __tablename__ = "audit_log"
    __table_args__ = (UniqueConstraint("hash"), Index("ix_audit_log_action", "action"))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    ts: Mapped[datetime]
    actor: Mapped[str]
    action: Mapped[str]
    target_type: Mapped[str | None]
    target_id: Mapped[str | None]
    detail: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    ip: Mapped[str | None]
    request_id: Mapped[str | None]
    prev_hash: Mapped[str]
    hash: Mapped[str]


class Feedback(Base):
    __tablename__ = "feedback"
    __table_args__ = (Index("ix_feedback_alert_id", "alert_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    alert_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("alert.id"))
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("finding.id"))
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    verdict: Mapped[str]
    reason: Mapped[str] = mapped_column(server_default="")
    created_at: Mapped[datetime]


class SuppressionRule(Base):
    """误报抑制规则（设计文档 6.2）：处理器在富化与评分之前检查，命中则不生成 Finding 与告警。"""

    __tablename__ = "suppression_rule"
    __table_args__ = (Index("ix_suppression_rule_project_id_value", "project_id", "value"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    kind: Mapped[str]  # domain / registered_domain
    value: Mapped[str]
    reason: Mapped[str] = mapped_column(server_default="")
    created_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    source_alert_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("alert.id"))
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_user.id"))


class Takedown(Base):
    """下架投诉（设计文档 12.1）：一条记录 = 向一个投诉对象的一次投诉；平台不自动发送。"""

    __tablename__ = "takedown"
    __table_args__ = (
        Index("ix_takedown_alert_id", "alert_id"),
        Index("ix_takedown_state", "state"),
        Index("ix_takedown_project_id_domain", "project_id", "domain"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    alert_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("alert.id"))
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("finding.id"))
    domain: Mapped[str]  # 主机名（URL 告警取其主机）；下架后监视与复活判断按它
    target: Mapped[dict[str, Any]]  # 投诉对象快照：kind、id、name、email、url、basis、detail、note
    language: Mapped[str]
    subject: Mapped[str]
    body: Mapped[str]
    # draft / approved / submitted / acknowledged / removed / rejected / cancelled / reappeared
    state: Mapped[str] = mapped_column(server_default="draft")
    created_by: Mapped[int] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    approved_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    external_ref: Mapped[str | None]  # 对方（注册商、托管商）的工单号
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    approved_at: Mapped[datetime | None]
    submitted_at: Mapped[datetime | None]
    acknowledged_at: Mapped[datetime | None]
    resolved_at: Mapped[datetime | None]  # 下架或被拒绝的时间
    due_at: Mapped[datetime | None]  # SLA 到期时间；到期未处理则提醒
    reminders: Mapped[int] = mapped_column(server_default="0")
    reappeared_alert_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("alert.id"))


class TakedownEvent(Base):
    __tablename__ = "takedown_event"
    __table_args__ = (Index("ix_takedown_event_takedown_id", "takedown_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    takedown_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("takedown.id"))
    ts: Mapped[datetime]
    actor: Mapped[str]  # 用户名；系统动作为 "system"
    from_state: Mapped[str | None]
    to_state: Mapped[str]
    note: Mapped[str] = mapped_column(server_default="")


class ApiToken(Base):
    """机器对机器的 API Token（设计文档 15）：只存哈希；作用域与到期时间；命令行签发。"""

    __tablename__ = "api_token"
    __table_args__ = (UniqueConstraint("name"), UniqueConstraint("token_hash"))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    name: Mapped[str]
    token_hash: Mapped[str]
    prefix: Mapped[str]  # 令牌前 12 个字符，便于在日志与列表中识别
    scopes: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    created_by: Mapped[str]
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]


class OidcLogin(Base):
    """进行中的单点登录（一次性，10 分钟过期）。主键是 state 的 SHA-256；state 本身不入库。"""

    __tablename__ = "oidc_login"
    __table_args__ = (Index("ix_oidc_login_expires_at", "expires_at"),)

    id: Mapped[str] = mapped_column(primary_key=True)
    binding_hash: Mapped[str]  # 浏览器绑定 Cookie 的 SHA-256：回调必须来自发起登录的同一浏览器
    nonce: Mapped[str]
    code_verifier: Mapped[str]
    next_path: Mapped[str]
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime]


class ExposedAccount(Base):
    """泄露事件中出现的本机构邮箱（设计文档 2.3、2.5）：个人信息，只给有 exposure:accounts 权限的人看，到期删除。"""

    __tablename__ = "exposed_account"
    __table_args__ = (
        UniqueConstraint("finding_id", "email"),
        Index("ix_exposed_account_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("finding.id"))
    email: Mapped[str]  # 小写
    source: Mapped[str]  # 连接器 ID
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    pushed_at: Mapped[datetime | None]  # 推给 IT 的时间；None 表示待推送


class LeakPost(Base):
    """Ransomware aggregator post metadata, retained for vendor rematching."""

    __tablename__ = "leak_post"
    __table_args__ = (UniqueConstraint("key"), Index("ix_leak_post_discovered", "discovered"))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    key: Mapped[str]
    group_name: Mapped[str]
    victim: Mapped[str]
    domain: Mapped[str | None]
    country: Mapped[str | None]
    activity: Mapped[str | None]
    discovered: Mapped[datetime]
    published: Mapped[datetime | None]
    sources: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    links: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    other_links: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    description: Mapped[str] = mapped_column(server_default="")
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]


class CodeRepo(Base):
    """Related public repository and next secret-scan time."""

    __tablename__ = "code_repo"
    __table_args__ = (
        UniqueConstraint("project_id", "repo"),
        Index("ix_code_repo_next_scan_at", "next_scan_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    repo: Mapped[str]
    first_seen: Mapped[datetime]
    last_hit_at: Mapped[datetime]
    last_scanned_at: Mapped[datetime | None]
    scan_status: Mapped[str] = mapped_column(server_default="pending")
    last_commit: Mapped[str | None]
    next_scan_at: Mapped[datetime]


class Document(Base):
    """Matched article metadata and excerpts; full article text is never persisted."""

    __tablename__ = "document"
    __table_args__ = (
        UniqueConstraint("url_normalized"),
        Index("ix_document_cluster_id", "cluster_id"),
        Index("ix_document_first_seen", "first_seen"),
        Index("ix_document_last_seen", "last_seen"),
        Index("ix_document_content_sha256", "content_sha256"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    url: Mapped[str | None]
    url_normalized: Mapped[str | None]
    title: Mapped[str] = mapped_column(server_default="")
    snippet: Mapped[str] = mapped_column(server_default="")
    contexts: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    search_text: Mapped[str] = mapped_column(server_default="")
    language: Mapped[str | None]
    source_name: Mapped[str] = mapped_column(server_default="")
    connectors: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    published_at: Mapped[datetime | None]
    content_sha256: Mapped[str]
    simhash: Mapped[int] = mapped_column(BigInteger)
    cluster_id: Mapped[int | None] = mapped_column(BigInteger)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]


class KevEntry(Base):
    """CISA KEV entries retained for software inventory rematching."""

    __tablename__ = "kev_entry"
    __table_args__ = (UniqueConstraint("cve_id"), Index("ix_kev_entry_date_added", "date_added"))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    cve_id: Mapped[str]
    vendor: Mapped[str]
    product: Mapped[str]
    name: Mapped[str] = mapped_column(server_default="")
    description: Mapped[str] = mapped_column(server_default="")
    required_action: Mapped[str] = mapped_column(server_default="")
    date_added: Mapped[date]
    due_date: Mapped[date | None]
    ransomware: Mapped[bool] = mapped_column(server_default=text("false"))
    notes: Mapped[str] = mapped_column(server_default="")
    cwes: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]


class Adjudication(Base):
    """LLM adjudication request and result; only the input hash is persisted."""

    __tablename__ = "adjudication"
    __table_args__ = (
        Index("ix_adjudication_status_created_at", "status", "created_at"),
        Index("ix_adjudication_finding_id", "finding_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("finding.id"))
    status: Mapped[str] = mapped_column(server_default="pending")
    held_severity: Mapped[str | None]
    attempts: Mapped[int] = mapped_column(server_default="0")
    leased_until: Mapped[datetime | None]
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    backend: Mapped[str | None]
    model: Mapped[str | None]
    prompt_version: Mapped[str | None]
    input_sha256: Mapped[str | None]
    verdict: Mapped[str | None]
    output: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    error: Mapped[str | None]


class Report(Base):
    """日报与周报；内容以 JSON 保存，逐个渠道记录送达。"""

    __tablename__ = "report"
    __table_args__ = (
        UniqueConstraint("project_id", "kind", "period_end"),
        Index("ix_report_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    kind: Mapped[str]
    period_start: Mapped[datetime]
    period_end: Mapped[datetime]
    created_at: Mapped[datetime]
    language: Mapped[str] = mapped_column(server_default="zh-CN")
    content: Mapped[dict[str, Any]] = mapped_column(server_default=EMPTY_JSON)
    sent_sinks: Mapped[list[str]] = mapped_column(server_default=EMPTY_ARRAY)
    sent_at: Mapped[datetime | None]


class Campaign(Base):
    """仿冒活动（设计文档 8 实体聚类）：共享独占基础设施的一组发现。

    candidate 由重算任务掌管；分析员确认（confirmed）后重算只追加待确认成员；
    dismissed 的成员集合（signature）不再作为候选出现。
    """

    __tablename__ = "campaign"
    __table_args__ = (
        Index("ix_campaign_project_id_state", "project_id", "state"),
        Index("ix_campaign_project_id_signature", "project_id", "signature"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    state: Mapped[str]  # candidate / confirmed / dismissed
    name: Mapped[str | None]  # 为空时页面显示默认名
    note: Mapped[str] = mapped_column(server_default="")
    signature: Mapped[str]  # 成员 finding_id 升序拼接的 SHA-256
    # 最近一次重算时被忽略的共享值：[{kind, value, count}]
    ignored: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB(), server_default=text("'[]'::jsonb")
    )
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    confirmed_at: Mapped[datetime | None]
    confirmed_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_user.id"))


class CampaignMember(Base):
    __tablename__ = "campaign_member"
    __table_args__ = (Index("ix_campaign_member_finding_id", "finding_id"),)

    campaign_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("campaign.id", ondelete="CASCADE"),
        primary_key=True,
    )
    finding_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("finding.id"), primary_key=True)
    state: Mapped[str]  # member / pending / excluded
    # 连入依据：[{kind, value, with_finding}]，最多 5 条
    signals: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB(), server_default=text("'[]'::jsonb")
    )
    added_at: Mapped[datetime]
    decided_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("app_user.id"))
    decided_at: Mapped[datetime | None]


class DashboardLayout(Base):
    """总览页布局：每个用户至多一行；user_id 为空的一行是机构默认布局。

    "机构默认只有一行"由迁移 0020 中的部分唯一索引 uq_dashboard_layout_default 保证
    （表达式索引，不在模型中声明）。
    """

    __tablename__ = "dashboard_layout"
    __table_args__ = (UniqueConstraint("user_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("app_user.id", ondelete="CASCADE"),
    )
    layout: Mapped[dict[str, Any]] = mapped_column(JSONB())
    updated_at: Mapped[datetime]
    updated_by: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("app_user.id", ondelete="SET NULL"),
    )


class LlmProvider(Base):
    """大模型供应商。密钥与代理以 AES-GCM 密文保存（opti.core.secretbox，AAD 绑定行与字段），
    接口只返回密钥末 4 位与去掉凭据的代理地址。"""

    __tablename__ = "llm_provider"
    __table_args__ = (UniqueConstraint("name"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    name: Mapped[str]
    preset: Mapped[str]
    base_url: Mapped[str]
    model: Mapped[str]
    api_key_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    api_key_hint: Mapped[str | None]
    proxy_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    proxy_hint: Mapped[str | None]
    json_mode: Mapped[bool]
    temperature: Mapped[float | None] = mapped_column(Double)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    last_test_at: Mapped[datetime | None]
    last_test_ok: Mapped[bool | None]
    last_test_error: Mapped[str | None]
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    updated_by: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("app_user.id", ondelete="SET NULL")
    )


class LlmSettings(Base):
    """大模型研判全局设置，只有 id = 1 一行；没有这一行时按默认值（研判关闭）。"""

    __tablename__ = "llm_settings"
    __table_args__ = (
        CheckConstraint("id = 1", name="singleton"),
        CheckConstraint(
            "primary_id IS NULL OR backup_id IS NULL OR primary_id <> backup_id",
            name="distinct_providers",
        ),
        CheckConstraint(
            "0 <= gray_zone_low AND gray_zone_low <= gray_zone_high AND gray_zone_high <= 100",
            name="gray_zone",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    enabled: Mapped[bool]
    primary_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("llm_provider.id", ondelete="RESTRICT")
    )
    backup_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("llm_provider.id", ondelete="RESTRICT")
    )
    gray_zone_low: Mapped[int] = mapped_column(Integer)
    gray_zone_high: Mapped[int] = mapped_column(Integer)
    max_per_run: Mapped[int] = mapped_column(Integer)
    max_attempts: Mapped[int] = mapped_column(Integer)
    max_wait_minutes: Mapped[int] = mapped_column(Integer)
    summary_language: Mapped[str]
    code_enabled: Mapped[bool] = mapped_column(server_default=text("false"))
    updated_at: Mapped[datetime]
    updated_by: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("app_user.id", ondelete="SET NULL")
    )
    # 研判 worker 每轮写入自己看到的情况（与 API 是不同进程，主密钥可能只配了一边）
    worker_checked_at: Mapped[datetime | None]
    worker_problem: Mapped[str | None]


class ConfigRevision(Base):
    """Web 配置版本（设计 2026-10-12-web-config-phase1）。只追加；当前生效 = 该 kind 的最大 version。"""

    __tablename__ = "config_revision"
    __table_args__ = (
        UniqueConstraint("kind", "version"),
        CheckConstraint(
            "kind IN ('rules', 'organization', 'alerting', 'retention', 'campaigns', 'takedown', "
            "'takedown_templates', 'tickets', 'vendors', 'software', 'sharing', 'connectors', 'identity', 'operations')",
            name="kind",
        ),
        CheckConstraint("version >= 1", name="version_positive"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    kind: Mapped[str]
    version: Mapped[int] = mapped_column(Integer)
    content: Mapped[str]
    digest: Mapped[str]
    note: Mapped[str | None]
    restored_from: Mapped[int | None] = mapped_column(Integer)
    created_by: Mapped[str]
    created_at: Mapped[datetime]


class ConfigRuntimeStatus(Base):
    """各进程已加载的配置版本；version 0 表示来自文件。"""

    __tablename__ = "config_runtime_status"

    process: Mapped[str] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(primary_key=True)
    version: Mapped[int] = mapped_column(Integer)
    digest: Mapped[str]
    error: Mapped[str | None]
    updated_at: Mapped[datetime]


class ConfigSecret(Base):
    """Web 配置密钥：AES-GCM 密文（AAD 绑定 kind 与 name）；value_enc 为空表示已清除，屏蔽同名环境变量。"""

    __tablename__ = "config_secret"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('alerting', 'tickets', 'sharing', 'connectors', 'identity')", name="kind"
        ),
    )

    kind: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(primary_key=True)
    value_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    hint: Mapped[str | None]
    updated_by: Mapped[str]
    updated_at: Mapped[datetime]
