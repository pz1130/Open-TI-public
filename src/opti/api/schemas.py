"""接口请求与响应模型。前端类型由这些模型经 OpenAPI 生成（Task 8），改名会让前端编译失败。"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

from opti.tickets.client import TICKET_REF_PATTERN


class AuthProviders(BaseModel):
    local: bool
    oidc: bool
    oidc_label: str


class LogoutOut(BaseModel):
    logout_url: str | None  # 单点登录会话：前端随后跳到身份提供方登出


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1000)


class Me(BaseModel):
    auth_source: str
    username: str
    display_name: str
    roles: list[str]
    permissions: list[str]
    must_change_password: bool = False


AlertStatus = Literal["open", "acknowledged", "closed"]
Verdict = Literal["true_positive", "false_positive", "duplicate", "benign_known", "out_of_scope"]
SuppressKind = Literal["none", "domain", "registered_domain"]


class AttackTechnique(BaseModel):
    id: str
    name: str
    tactics: list[str]
    url: str


class AlertSummary(BaseModel):
    id: int
    severity: str
    status: str
    ignored: bool = False
    ignored_at: datetime | None = None
    category: str
    domain: str
    score: int
    reasons: list[str]
    attack_techniques: list[AttackTechnique]
    created_at: datetime
    notified_at: datetime | None
    evidence_status: str
    screenshot_id: int | None
    triage_verdict: str | None
    finding_id: int
    first_seen: datetime
    last_seen: datetime
    sources: list[str]


class AlertPage(BaseModel):
    items: list[AlertSummary]
    next_cursor: int | None
    total: int = 0


class FindingOut(BaseModel):
    id: int
    category: str
    score: int
    severity: str
    status: str
    score_breakdown: dict[str, int]
    match: dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    sources: list[str]


class ObservationOut(BaseModel):
    connector_id: str
    observed_at: datetime
    score: int


class EvidenceOut(BaseModel):
    id: int
    kind: str
    content_type: str
    sha256: str
    size: int
    captured_at: datetime
    node_id: str
    method: str
    source_url: str | None
    uploaded_by: str | None = None
    original_sha256: str | None = None


class FeedbackOut(BaseModel):
    verdict: str
    reason: str
    username: str
    created_at: datetime


class AlertHistoryItem(BaseModel):
    id: int
    severity: str
    status: str
    created_at: datetime


class RelatedAlert(BaseModel):
    id: int
    domain: str
    severity: str
    status: str
    last_seen: datetime
    signals: list[Literal["tls_sha256", "favicon_sha256"]]


CampaignState = Literal["candidate", "confirmed", "dismissed"]
MemberState = Literal["member", "pending", "excluded"]
CampaignSignal = Literal["tls_sha256", "favicon_sha256", "html_sha256", "ip"]


class AlertCampaign(BaseModel):
    id: int
    name: str | None
    label_value: str  # name 为空时前端用"<label_value> 等 N 个"作默认名
    member_count: int
    state: CampaignState
    member_state: MemberState


class CampaignLink(BaseModel):
    kind: CampaignSignal
    value: str
    with_finding: int


class CampaignIgnored(BaseModel):
    kind: CampaignSignal
    value: str
    count: int


class CampaignSummary(BaseModel):
    id: int
    state: CampaignState
    name: str | None
    label_value: str
    member_count: int
    pending_count: int
    active_alerts: int
    top_severity: str | None
    signal_kinds: list[CampaignSignal]
    updated_at: datetime


class CampaignPage(BaseModel):
    items: list[CampaignSummary]
    total: int


class CampaignMemberOut(BaseModel):
    finding_id: int
    entity_type: str
    value: str
    state: MemberState
    signals: list[CampaignLink]
    alert_id: int | None
    severity: str | None
    status: str | None
    assignee: str | None
    verdict: str | None
    takedown_state: str | None
    added_at: datetime


class CampaignDetail(BaseModel):
    campaign: CampaignSummary
    note: str
    ignored: list[CampaignIgnored]
    confirmed_at: datetime | None
    confirmed_by: str | None
    members: list[CampaignMemberOut]


class CampaignUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=200)
    note: str | None = Field(default=None, max_length=2000)
    state: CampaignState | None = None


class MemberDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["accept", "reject", "remove"]


class CampaignBulk(BaseModel):
    model_config = ConfigDict(extra="forbid")  # 批量操作不接受抑制参数

    action: Literal["verdict", "acknowledge", "close"]
    verdict: Verdict | None = None
    reason: str = Field(default="", max_length=2000)


class CampaignBulkOut(BaseModel):
    updated: list[int]
    skipped: int


class WatchBrief(BaseModel):
    id: int
    state: str
    next_check_at: datetime
    last_checked_at: datetime | None
    expires_at: datetime | None


Language = Literal["zh-CN", "en-US"]
TransitionTo = Literal[
    "approved", "draft", "cancelled", "submitted", "acknowledged", "removed", "rejected"
]


class TargetOut(BaseModel):
    kind: str
    id: str
    name: str
    email: str | None
    url: str | None
    basis: str
    detail: str
    note: str


class TargetsOut(BaseModel):
    host: str
    targets: list[TargetOut]
    missing_hosting: list[str]


class TakedownIn(BaseModel):
    target_id: str = Field(min_length=1, max_length=200)
    language: Language = "zh-CN"


class TakedownOut(BaseModel):
    id: int
    alert_id: int
    domain: str
    target: TargetOut
    language: str
    subject: str
    body: str
    state: str
    created_by: str
    approved_by: str | None
    external_ref: str | None
    created_at: datetime
    updated_at: datetime
    submitted_at: datetime | None
    resolved_at: datetime | None
    due_at: datetime | None
    reminders: int
    reappeared_alert_id: int | None


class TakedownEventOut(BaseModel):
    ts: datetime
    actor: str
    from_state: str | None
    to_state: str
    note: str


class TakedownDetail(BaseModel):
    takedown: TakedownOut
    events: list[TakedownEventOut]
    escalation: list[TargetOut]


class TakedownPage(BaseModel):
    items: list[TakedownOut]
    next_cursor: int | None
    total: int = 0


class TakedownEdit(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=20000)


class TakedownTransition(BaseModel):
    to: TransitionTo
    note: str = Field(default="", max_length=2000)
    external_ref: str | None = Field(default=None, max_length=200)


class TakedownBrief(BaseModel):
    id: int
    state: str
    target_name: str
    target_kind: str
    updated_at: datetime


class TargetStatOut(BaseModel):
    name: str
    kind: str
    total: int
    removed: int
    rejected: int
    median_response_hours: float | None


class TakedownStats(BaseModel):
    by_state: dict[str, int]
    mttr_hours: float | None
    targets: list[TargetStatOut]


class TicketOut(BaseModel):
    ref: str | None
    status: str | None
    pushed_at: datetime | None
    synced_at: datetime | None
    available: bool  # 是否配置了工单推送
    url: str | None = None  # Jira / ServiceNow 工单跳转地址


class TicketRefIn(BaseModel):
    ticket_ref: str = Field(pattern=TICKET_REF_PATTERN)


class TicketCallbackIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    alert_id: int = Field(ge=1)
    ticket_ref: str | None = Field(default=None, pattern=TICKET_REF_PATTERN)
    status: str | None = Field(default=None, min_length=1, max_length=50)


class AlertDetail(BaseModel):
    takedowns: list[TakedownBrief]
    ticket: TicketOut
    alert: AlertSummary
    finding: FindingOut
    enrichment: dict[str, Any]
    observations: list[ObservationOut]
    evidence: list[EvidenceOut]
    feedback: list[FeedbackOut]
    history: list[AlertHistoryItem]
    related_alerts: list[RelatedAlert]
    campaign: AlertCampaign | None
    watch: WatchBrief | None
    entity_type: str
    assignee: str | None
    translation_available: bool


class TranslationIn(BaseModel):
    target_language: str = Field(pattern=r"^[a-z]{2}$")


class TranslationOut(BaseModel):
    source_language: str
    target_language: str
    title: str
    contexts: list[str]


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    assign_to_me: bool | None = None
    ignored: StrictBool | None = None


class FeedbackIn(BaseModel):
    verdict: Verdict
    reason: str = Field(default="", max_length=2000)
    suppress: SuppressKind = "none"
    suppress_days: int | None = Field(default=None, ge=1, le=3650)


class WatchInspectionOut(BaseModel):
    observed_at: datetime
    verdict: str
    source: str
    title: str = ""
    text_excerpt: str = ""
    final_url: str | None = None
    redirects: list[str] = Field(default_factory=list)
    status: int | None = None
    brand_terms: list[str] = Field(default_factory=list)
    has_password_field: bool = False
    capture_status: str
    evidence: list[EvidenceOut] = Field(default_factory=list)
    error: str | None = None


class WatchOut(BaseModel):
    id: int
    domain: str
    state: str
    reason: str
    created_at: datetime
    last_checked_at: datetime | None
    next_check_at: datetime
    expires_at: datetime | None
    inspection: WatchInspectionOut | None = None


class WatchPage(BaseModel):
    items: list[WatchOut]
    next_cursor: int | None
    total: int = 0


class WatchCheckOut(BaseModel):
    status: Literal["queued"] = "queued"
    watch_id: int
    request_id: str


class WatchIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    reason: str = Field(min_length=1, max_length=500)


class WatchObservationOut(BaseModel):
    id: int | None = None
    observed_at: datetime
    state: str
    changes: list[str]
    fingerprint: dict[str, Any]
    inspection: WatchInspectionOut | None = None


KeywordKindIn = Literal["brand", "restricted", "official", "lookalike"]
Affix = Annotated[str, Field(min_length=1, max_length=63)]


class KeywordStatOut(BaseModel):
    value: str
    findings_30d: int | None  # 统计超时为 null
    last_seen: datetime | None


class RestrictedKeywordOut(KeywordStatOut):
    affixes: list[str]


class BackfillRunOut(BaseModel):
    status: str
    started_at: datetime
    ended_at: datetime | None
    items: int


class BackfillOut(BaseModel):
    status: Literal["queued", "running", "too_soon", "unavailable"]
    reason: str | None = None
    next_allowed_at: datetime | None = None
    run_id: int | None = None


class DomainKeywordsOut(BaseModel):
    version: int
    short_token_max_len: int
    brand: list[KeywordStatOut]
    restricted: list[RestrictedKeywordOut]
    official: list[KeywordStatOut]
    lookalike: list[str]
    last_runs: dict[str, BackfillRunOut | None]


class KeywordIn(BaseModel):
    kind: KeywordKindIn
    value: str = Field(min_length=1, max_length=253)
    affixes: list[Affix] = Field(default_factory=list, max_length=50)


class AffixesIn(BaseModel):
    affixes: list[Affix] = Field(max_length=50)


class KeywordChangeOut(BaseModel):
    version: int
    changed: bool
    backfill: dict[str, BackfillOut]


class KeywordHitOut(BaseModel):
    finding_id: int
    domain: str
    score: int
    severity: str
    last_seen: datetime
    alert_id: int | None
    alert_status: str | None


class KeywordHitPage(BaseModel):
    items: list[KeywordHitOut]
    total: int


class SuppressionOut(BaseModel):
    id: int
    kind: str
    value: str
    reason: str
    created_by: str | None
    source_alert_id: int | None
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    active: bool


class SuppressionIn(BaseModel):
    kind: Literal["domain", "registered_domain"]
    value: str = Field(min_length=3, max_length=253)
    reason: str = Field(min_length=1, max_length=2000)
    expires_days: int | None = Field(default=None, ge=1, le=3650)


class AuditEntry(BaseModel):
    id: int
    ts: datetime
    actor: str
    action: str
    target_type: str | None
    target_id: str | None
    detail: dict[str, Any]
    ip: str | None
    request_id: str | None


class AuditPage(BaseModel):
    items: list[AuditEntry]
    next_cursor: int | None
    total: int = 0


class AuditVerifyOut(BaseModel):
    ok: bool
    first_broken_id: int | None
    checked_at: datetime


class RulesTestIn(BaseModel):
    domains: list[Annotated[str, Field(max_length=253)]] = Field(
        default_factory=list, max_length=200
    )
    text: str = Field(default="", max_length=50_000)
    draft_yaml: str | None = Field(default=None, max_length=200_000)


class DomainReportOut(BaseModel):
    input: str
    status: str  # match / official / known_lookalike / no_match
    domain: str | None = None
    registered: str | None = None
    reasons: list[dict[str, Any]] = Field(default_factory=list)
    score: dict[str, Any] | None = None


class TextHitOut(BaseModel):
    set_name: str
    term: str
    mode: str
    role: str
    context: str  # 归一化视图中的上下文片段；高亮在片段内查找 term，不对应原文偏移


class RulesTestOut(BaseModel):
    source: Literal["current", "draft"]
    project: str
    domains: list[DomainReportOut]
    text_hits: list[TextHitOut]


class ExposureOut(BaseModel):
    source: str
    kind: str
    domain: str
    title: str
    breach_date: str | None
    added_date: str | None
    data_classes: list[str]
    verified: bool
    fabricated: bool
    sensitive: bool
    spam_list: bool
    stealer_log: bool
    affected: int
    accounts_total: int
    accounts_pending: int
    can_push: bool


class ExposedAccountOut(BaseModel):
    email: str
    first_seen: datetime
    last_seen: datetime
    pushed_at: datetime | None


class ExposurePushOut(BaseModel):
    pushed: int
    channel: str
    ticket_ref: str | None


class DocumentOut(BaseModel):
    id: int
    url: str | None
    title: str
    snippet: str
    contexts: list[str]
    language: str | None
    source_name: str
    connectors: list[str]
    published_at: datetime | None
    first_seen: datetime
    cluster_id: int | None


class DocumentPage(BaseModel):
    items: list[DocumentOut]
    next_cursor: int | None
    total: int = 0


ReportKind = Literal["daily", "weekly", "monthly"]


class ReportSummary(BaseModel):
    id: int
    kind: ReportKind
    title: str
    period_start: datetime
    period_end: datetime
    created_at: datetime
    sent_at: datetime | None
    totals: dict[str, int]


class ReportOut(ReportSummary):
    content: dict[str, Any]


class ReportPage(BaseModel):
    items: list[ReportSummary]
    next_cursor: int | None
    total: int = 0


class NamedCount(BaseModel):
    name: str
    count: int


class TrendDay(BaseModel):
    day: str
    critical: int
    high: int
    medium: int
    low: int


class MttdOut(BaseModel):
    source: str
    count: int
    median_hours: float | None
    within_target: float | None
    target_hours: float


class AlertBrief(BaseModel):
    alert_id: int
    severity: str
    category: str
    subject: str
    score: int
    created_at: datetime
    overdue_hours: float | None = None


class DashboardOut(BaseModel):
    days: int
    generated_at: datetime
    open_alerts: dict[str, int]
    new_alerts: int
    new_findings: int
    trend: list[TrendDay]
    by_category: list[NamedCount]
    by_source: list[NamedCount]
    mttd: list[MttdOut]
    mttr_hours: float | None
    overdue: dict[str, int]
    overdue_alerts: list[AlertBrief]
    top_alerts: list[AlertBrief]
    hosting_countries: list[NamedCount]
    hosting_networks: list[NamedCount]


GRID_COLUMNS = 12
LAYOUT_MAX_BYTES = 16_384
ParamKey = Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,32}$")]
ParamValue = StrictBool | StrictInt | Annotated[StrictStr, StringConstraints(max_length=64)] | None


class LayoutWidget(BaseModel):
    """总览页上的一张卡片；type 只校验格式，前端忽略不认识的类型。"""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,16}$")
    type: str = Field(pattern=r"^[a-z_]{1,32}$")
    x: int = Field(ge=0, le=GRID_COLUMNS - 1)
    y: int = Field(ge=0, le=500)
    w: int = Field(ge=1, le=GRID_COLUMNS)
    h: int = Field(ge=1, le=24)
    params: dict[ParamKey, ParamValue] = Field(max_length=8)

    @model_validator(mode="after")
    def _fits_grid(self) -> Self:
        if self.x + self.w > GRID_COLUMNS:
            raise ValueError("widget exceeds grid width")
        return self


class LayoutSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    days: int = Field(ge=1, le=365)
    widgets: list[LayoutWidget] = Field(max_length=30)

    @model_validator(mode="after")
    def _check(self) -> Self:
        ids = [w.id for w in self.widgets]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate widget id")
        if len(self.model_dump_json().encode()) > LAYOUT_MAX_BYTES:
            raise ValueError("layout too large")
        return self


class LayoutOut(BaseModel):
    layout: LayoutSpec | None
    source: Literal["user", "default", "builtin"]


class DefaultLayoutOut(BaseModel):
    layout: LayoutSpec | None


class CredentialState(BaseModel):
    name: str
    required: bool
    configured: bool | None  # None：凭据在采集节点上，节点尚未上报
    problem: str | None = None  # 库中的凭据无法解密等


class RunBrief(BaseModel):
    started_at: datetime
    ended_at: datetime | None
    status: str
    items: int
    errors: int
    message: str
    node_id: str | None


class ConnectorOut(BaseModel):
    id: str
    name: str
    category: str
    tier: str
    kind: list[str]
    egress: str
    homepage: str | None
    tos_url: str | None
    commercial_use: str
    last_reviewed: date | None
    pii_risk: str
    compliance_notes: str
    schedule: str | None
    enabled: bool
    license_approved: bool
    license_ref: str | None
    plan: str
    runnable: bool | None
    reason: str
    location: str
    credentials: list[CredentialState]
    health: str
    last_run: RunBrief | None
    last_success_at: datetime | None
    runs_24h: int
    errors_24h: int


class ConnectorConfigOut(BaseModel):
    id: str
    darkweb: bool
    enabled: bool
    plan: str
    plans: list[str]
    config: dict[str, Any]
    config_schema: dict[str, Any]
    credentials: list[CredentialState]
    license_approved: bool
    license_ref: str | None
    darkweb_approval_ref: str | None
    encryption_key: bool
    version: int  # kind connectors 的当前版本
    schedule: str | None = None
    default_schedule: str | None = None
    schedulable: bool = False


class ConnectorConfigIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    plan: str
    config: dict[str, Any]
    # Omitted names retain their stored value. null clears; nonempty string replaces.
    secrets: dict[str, str | None] = Field(default_factory=dict)
    schedule: str | None = None


class ConnectorHistoryOut(BaseModel):
    version: int
    created_by: str
    created_at: datetime
    note: str | None
    restored_from: int | None
    changed: list[str]  # 这一版改动了的字段
    diff: str  # 该连接器一项在前后两版之间的 YAML 差异
    restorable: bool  # 参数与当前不同，可以恢复


class ConnectorRestoreIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=1)


class ConnectorApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    license_approved: bool
    license_ref: str | None = None
    darkweb_approval_ref: str | None = None


class SubmissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=2048)
    category: Literal["impersonation_account", "fraud_scam", "phishing_site", "clone_site"]
    severity: Literal["medium", "high", "critical"]
    description: str = Field(min_length=1, max_length=2000)
    observed_at: datetime | None = None


class SubmissionOut(BaseModel):
    alert_id: int
    finding_id: int
    url: str
    platform: str | None
    created_alert: bool


class PlatformCheckOut(BaseModel):
    url: str | None
    platform: str | None
    platform_name: str | None
    fetch: bool
    error: str | None


# 大模型研判配置（设计 2026-10-10-llm-providers）
ProviderName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
ModelName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
# 只接受可打印 ASCII：密钥要放进 HTTP 请求头，混入中文等字符会在调用时才失败
ApiKey = Annotated[str, StringConstraints(min_length=1, max_length=512, pattern=r"^[\x21-\x7e]+$")]
UrlText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
Temperature = Annotated[float, Field(ge=0, le=2)]
LLM_REQUIRED = ("name", "base_url", "model", "json_mode", "timeout_seconds")


class LlmPresetOut(BaseModel):
    key: str
    name: str
    group: Literal["international", "domestic", "local"]
    protocol: Literal["anthropic", "openai"]
    auth: Literal["x-api-key", "bearer", "api-key"]
    base_url: str
    model: str
    json_mode: bool
    temperature: float | None
    list_models: Literal["yes", "try", "no"]
    key_required: bool
    insecure_http: bool


class LlmSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool
    primary_id: int | None
    backup_id: int | None
    gray_zone_low: int = Field(ge=0, le=100)
    gray_zone_high: int = Field(ge=0, le=100)
    max_per_run: int = Field(ge=1, le=200)
    max_attempts: int = Field(ge=1, le=10)
    max_wait_minutes: int = Field(ge=1, le=1440)
    summary_language: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32)
    ]
    code_enabled: StrictBool = False  # 研判代码仓库密钥（设计 2026-10-17）；旧客户端不带时为关闭

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.gray_zone_low > self.gray_zone_high:
            raise ValueError("gray_zone_low must not exceed gray_zone_high")
        if self.backup_id is not None and self.primary_id is None:
            raise ValueError("a backup provider requires a primary provider")
        if self.primary_id is not None and self.primary_id == self.backup_id:
            raise ValueError("primary and backup must be different providers")
        if self.enabled and self.primary_id is None:
            raise ValueError("enabling adjudication requires a primary provider")
        return self


class LlmSettingsOut(LlmSettingsIn):
    updated_at: datetime | None


class LlmProviderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ProviderName
    preset: str = Field(min_length=1, max_length=32)
    base_url: UrlText
    model: ModelName
    api_key: ApiKey | None = None
    proxy: UrlText | None = None
    json_mode: StrictBool = True
    temperature: Temperature | None = 0.0
    timeout_seconds: int = Field(default=60, ge=1, le=300)


class LlmProviderPatch(BaseModel):
    """缺省 = 不变；api_key、proxy、temperature 传 null = 清除；其余字段不能为 null。"""

    model_config = ConfigDict(extra="forbid")
    name: ProviderName | None = None
    base_url: UrlText | None = None
    model: ModelName | None = None
    api_key: ApiKey | None = None
    proxy: UrlText | None = None
    json_mode: StrictBool | None = None
    temperature: Temperature | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=300)

    @model_validator(mode="after")
    def _not_null(self) -> Self:
        for name in LLM_REQUIRED:
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        return self


class LlmProviderOut(BaseModel):
    id: int
    name: str
    preset: str
    group: str
    base_url: str
    model: str
    api_key_set: bool
    api_key_hint: str | None
    proxy_hint: str | None
    json_mode: bool
    temperature: float | None
    timeout_seconds: int
    last_test_at: datetime | None
    last_test_ok: bool | None
    last_test_error: str | None
    in_use: Literal["primary", "backup"] | None
    updated_at: datetime


class LlmModelsOut(BaseModel):
    models: list[str]


class LlmTestOut(BaseModel):
    ok: bool
    provider: str
    model: str
    verdict: str | None
    confidence: float | None
    latency_ms: int
    error: str | None


class LlmStatusOut(BaseModel):
    encryption_key: bool
    problem: str | None
    queue: int
    done_24h: int
    failed_24h: int
    worker_problem: str | None  # 研判 worker 最近一轮看到的问题
    worker_checked_at: datetime | None


class ConfigErrorOut(BaseModel):
    path: str
    message: str
    line: int | None = None


class ConfigOut(BaseModel):
    kind: str
    version: int
    source: Literal["file", "db"]
    file_path: str | None = None
    yaml: str
    data: dict[str, Any]
    digest: str
    created_by: str | None = None
    created_at: datetime | None = None
    note: str | None = None
    restored_from: int | None = None
    builtin: dict[str, Any] | None = None


class TemplatePreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    language: Literal["zh-CN", "en-US"]
    kind: Literal["registrar", "hosting", "cdn", "report", "platform"]
    text: str = Field(max_length=16_000)


class TemplatePreviewOut(BaseModel):
    subject: str
    body: str
    errors: list[str]


class RematchOut(BaseModel):
    status: Literal["none", "queued", "done", "failed"]
    version: int | None = None
    alerts: int | None = None
    error: str | None = None
    at: datetime | None = None


class SharingTestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: Literal["syslog", "webhook"]
    sharing: dict[str, Any]
    secrets: dict[str, Annotated[str, Field(max_length=4096)] | None] = Field(default_factory=dict)


class ConfigValidateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yaml: str | None = Field(default=None, max_length=200_000)
    data: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> ConfigValidateIn:
        if (self.yaml is None) == (self.data is None):
            raise ValueError("yaml 与 data 必须且只能提供一个")
        return self


class ConfigValidateOut(BaseModel):
    ok: bool
    yaml: str | None = None
    data: dict[str, Any] | None = None
    errors: list[ConfigErrorOut] = Field(default_factory=list)


class ConfigSaveIn(ConfigValidateIn):
    note: str | None = Field(default=None, max_length=200)
    base_version: int = Field(ge=0)
    confirm_project_change: bool = False
    confirm_oidc_change: bool = False
    confirm_retention: bool = False
    secrets: dict[str, Annotated[str, Field(max_length=4096)] | None] | None = None


class ConfigRestoreIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_version: int = Field(ge=0)
    confirm_project_change: bool = False
    confirm_oidc_change: bool = False
    confirm_retention: bool = False


class ConfigSecretOut(BaseModel):
    name: str
    set: bool
    hint: str | None
    source: Literal["db", "env", "none"]
    updated_by: str | None
    updated_at: datetime | None


class ConfigSecretsOut(BaseModel):
    encryption_key: bool  # 服务器是否配置了 OPTI_ENCRYPTION_KEY；否则界面禁用密钥输入框
    secrets: list[ConfigSecretOut]


class AlertingTestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: dict[str, Any]
    smtp: dict[str, Any] | None = None
    secrets: dict[str, Annotated[str, Field(max_length=4096)]] = Field(default_factory=dict)


class AlertingTestOut(BaseModel):
    ok: bool
    error: str | None = None


class TicketsTestOut(BaseModel):
    ok: bool
    kind: Literal["auth", "rejected", "unavailable", "incomplete"] | None = None
    detail: str | None = None


class ConfigRevisionOut(BaseModel):
    version: int
    digest: str
    note: str | None
    restored_from: int | None
    created_by: str
    created_at: datetime


class ConfigRevisionDetailOut(ConfigRevisionOut):
    yaml: str
    diff: str


class ConfigProcessOut(BaseModel):
    process: str
    kind: str
    version: int
    digest: str
    error: str | None
    updated_at: datetime
    stale: bool
    edge: bool


class ConfigStatusOut(BaseModel):
    current: dict[str, int]
    current_digest: dict[str, str]
    processes: list[ConfigProcessOut]
