"""可由管理员调整的业务运行参数；协议、权限与资源安全边界仍由代码约束。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from opti.sdk.schedules import valid_cron

TASK_CRONS = {
    "check_social_accounts": "*/10 * * * *",
    "check_certificates": "*/10 * * * *",
    "recheck_watchlist": "*/10 * * * *",
    "dispatch_pending": "*/5 * * * *",
    "adjudicate_pending": "*/2 * * * *",
    "daily_report": "0 1 * * *",
    "weekly_report": "5 1 * * 1",
    "monthly_report": "10 1 * * *",
    "send_reports": "*/30 * * * *",
    "push_siem": "* * * * *",
    "refresh_tranco": "30 1 * * *",
    "maintain_partitions": "0 0 * * *",
    "sweep_connector_runs": "*/10 * * * *",
    "capture_evidence": "*/10 * * * *",
    "enrich_hosting": "*/30 * * * *",
    "takedown_reminders": "15 * * * *",
    "push_tickets": "*/5 * * * *",
    "push_exposures": "*/30 * * * *",
    "recompute_campaigns": "*/10 * * * *",
    "apply_retention": "40 2 * * *",
    "rematch_leak_posts": "30 3 * * *",
    "scan_code_repos": "*/30 * * * *",
    "rematch_kev": "0 4 * * *",
}


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WatchPolicy(PolicyModel):
    young_days: int = Field(default=7, ge=1, le=365)
    mature_days: int = Field(default=30, ge=1, le=3650)
    urgent_hours: int = Field(default=4, ge=1, le=168)
    normal_hours: int = Field(default=24, ge=1, le=720)
    dormant_hours: int = Field(default=168, ge=1, le=2160)
    release_after_days: int = Field(default=90, ge=1, le=3650)
    removed_watch_days: int = Field(default=90, ge=1, le=3650)
    watch_below_score: int = Field(default=65, ge=1, le=100)

    @model_validator(mode="after")
    def periods(self) -> WatchPolicy:
        if self.mature_days <= self.young_days or self.release_after_days < self.mature_days:
            raise ValueError("成熟天数须大于新发现天数，释放等待天数不得小于成熟天数")
        if not self.urgent_hours <= self.normal_hours <= self.dormant_hours:
            raise ValueError("复查间隔须按高风险、普通、长期监视依次递增")
        return self


class CertificatePolicy(PolicyModel):
    max_hosts: int = Field(default=1000, ge=1, le=10000)
    scan_timeout_seconds: int = Field(default=540, ge=120, le=840)
    interval_hours: int = Field(default=24, ge=1, le=720)
    retry_hours: int = Field(default=1, ge=1, le=168)
    retire_after_days: int = Field(default=30, ge=1, le=3650)
    urgent_expiry_days: int = Field(default=7, ge=1, le=365)


class DeliveryPolicy(PolicyModel):
    alert_window_days: int = Field(default=7, ge=1, le=365)
    report_retry_days: int = Field(default=7, ge=1, le=365)
    siem_window_days: int = Field(default=7, ge=1, le=365)
    ticket_window_hours: int = Field(default=24, ge=1, le=8760)
    backoff_minutes: tuple[int, ...] = Field(default=(5, 10, 20, 30), min_length=1, max_length=10)

    @field_validator("backoff_minutes")
    @classmethod
    def backoff(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if list(value) != sorted(value) or any(n < 1 or n > 1440 for n in value):
            raise ValueError("退避时间须递增，且每项在 1–1440 分钟之间")
        return value


class ScanPolicy(PolicyModel):
    repo_rescan_days: int = Field(default=30, ge=1, le=3650)
    repo_retry_hours: int = Field(default=24, ge=1, le=8760)
    evidence_attempts: int = Field(default=3, ge=1, le=10)
    leak_rematch_days: int = Field(default=365, ge=1, le=3650)
    enrichment_timeout_seconds: int = Field(default=120, ge=10, le=120)
    stale_if_error_hours: int = Field(default=24, ge=0, le=168)
    document_near_days: int = Field(default=30, ge=1, le=365)


class BatchPolicy(PolicyModel):
    social_accounts: int = Field(default=100, ge=1, le=1000)
    certificates: int = Field(default=100, ge=1, le=1000)
    watchlist: int = Field(default=100, ge=1, le=1000)
    evidence: int = Field(default=20, ge=1, le=200)
    hosting: int = Field(default=50, ge=1, le=500)
    reminders: int = Field(default=50, ge=1, le=500)
    tickets: int = Field(default=20, ge=1, le=200)
    exposures: int = Field(default=20, ge=1, le=200)
    code_repos: int = Field(default=5, ge=1, le=50)
    siem: int = Field(default=500, ge=1, le=5000)
    retention: int = Field(default=5000, ge=1, le=5000)


class RiskPolicy(PolicyModel):
    low_score: int = Field(default=20, ge=1, le=97)
    medium_score: int = Field(default=40, ge=2, le=98)
    high_score: int = Field(default=65, ge=3, le=99)
    critical_score: int = Field(default=85, ge=4, le=100)
    alert_from: Literal["low", "medium", "high", "critical"] = "medium"
    sla_critical_hours: int = Field(default=4, ge=1, le=8760)
    sla_high_hours: int = Field(default=24, ge=1, le=8760)
    sla_medium_hours: int = Field(default=72, ge=1, le=8760)
    mttd_ct_hours: float = Field(default=1.0, gt=0, le=8760)
    mttd_nrd_hours: float = Field(default=24.0, gt=0, le=8760)
    llm_yes_points: int = Field(default=10, ge=0, le=100)
    llm_no_points: int = Field(default=-30, ge=-100, le=0)
    llm_unsure_points: int = Field(default=0, ge=-100, le=100)
    # 代码仓库密钥研判（设计 2026-10-17）：只在告警线以上调整排序
    llm_code_real_points: int = Field(default=10, ge=0, le=100)
    llm_code_example_points: int = Field(default=-15, ge=-100, le=0)
    llm_code_org_points: int = Field(default=10, ge=0, le=100)
    llm_code_related_points: int = Field(default=5, ge=0, le=100)
    llm_code_unrelated_points: int = Field(default=-10, ge=-100, le=0)

    @model_validator(mode="after")
    def thresholds(self) -> RiskPolicy:
        if not self.low_score < self.medium_score < self.high_score < self.critical_score:
            raise ValueError("风险等级分数须严格递增")
        return self


class PagePolicy(PolicyModel):
    sale_phrases: tuple[str, ...] = (
        "buy this domain",
        "this domain is for sale",
        "this domain may be for sale",
        "domain name is for sale",
        "domain is available for purchase",
        "purchase this domain",
        "get this domain",
        "domain is parked",
        "parked free",
        "域名出售",
        "域名转让",
        "购买此域名",
        "此域名正在出售",
        "该域名正在出售",
    )
    parking_hosts: tuple[str, ...] = (
        "sedo.com",
        "sedoparking.com",
        "afternic.com",
        "dan.com",
        "hugedomains.com",
        "buydomains.com",
        "parkingcrew.net",
        "bodis.com",
        "parklogic.com",
    )
    challenge_phrases: tuple[str, ...] = (
        "just a moment",
        "verify you are human",
        "checking your browser",
        "人机验证",
        "安全验证",
    )

    @field_validator("parking_hosts")
    @classmethod
    def hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        from opti.core.domains import parse_domain

        if len(value) > 200 or any(
            not parse_domain(host) or host != host.lower().rstrip(".") for host in value
        ):
            raise ValueError("停放平台须填写小写域名，最多 200 项")
        return value

    @field_validator("sale_phrases", "challenge_phrases")
    @classmethod
    def phrases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 200 or any(not p.strip() or len(p) > 200 for p in value):
            raise ValueError("每个特征词须为 1–200 个字符，最多 200 项")
        return tuple(p.strip().casefold() for p in value)


class OperationsConfig(PolicyModel):
    watchlist: WatchPolicy = Field(default_factory=WatchPolicy)
    certificates: CertificatePolicy = Field(default_factory=CertificatePolicy)
    delivery: DeliveryPolicy = Field(default_factory=DeliveryPolicy)
    scanning: ScanPolicy = Field(default_factory=ScanPolicy)
    batches: BatchPolicy = Field(default_factory=BatchPolicy)
    risk: RiskPolicy = Field(default_factory=RiskPolicy)
    pages: PagePolicy = Field(default_factory=PagePolicy)
    schedules: dict[str, str] = Field(default_factory=lambda: dict(TASK_CRONS))

    @field_validator("schedules")
    @classmethod
    def schedules_valid(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value) - TASK_CRONS.keys():
            raise ValueError("未知后台任务")
        if any(not valid_cron(v) for v in value.values()):
            raise ValueError("任务时间须为有效的五段 Cron 表达式（UTC）")
        return {**TASK_CRONS, **value}


_current = OperationsConfig()


def current() -> OperationsConfig:
    return _current


def install(config: OperationsConfig) -> None:
    global _current
    _current = config
