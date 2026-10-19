"""人工 URL 提交（设计文档 4.2 人工核查工作流）：分析员选定类别与级别，直接生成发现与告警。

平台名单内的链接沙箱不访问、不加监视，证据只靠分析员上传；其他链接照常截图取证。
只有主机本身像仿冒域名时才加入监视列表，sites.google.com、短链接等共享主机不监视。
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher
from opti.core.scoring import Category, Score, Severity, severity_for
from opti.core.urls import normalize_url
from opti.db import repo
from opti.db.models import Alert, AlertFinding, Finding
from opti.export.blocklist import protected_host
from opti.pipeline import watchlist
from opti.sdk.models import RawItem
from opti.takedown.config import TakedownConfig
from opti.takedown.hosting import alert_host, ip_literal

CONNECTOR_ID = "manual_submission"
CATEGORIES = frozenset(
    {
        Category.IMPERSONATION_ACCOUNT,
        Category.FRAUD_SCAM,
        Category.PHISHING_SITE,
        Category.CLONE_SITE,
    }
)
SEVERITY_SCORES = {Severity.MEDIUM: 50, Severity.HIGH: 75, Severity.CRITICAL: 90}
MAX_DESCRIPTION = 2000


class SubmissionError(ValueError):
    """提交内容不可接受（接口返回 422）。"""


@dataclass(frozen=True)
class Submission:
    url: str
    category: Category
    severity: Severity
    description: str
    observed_at: datetime | None = None


@dataclass(frozen=True)
class SubmissionResult:
    alert_id: int
    finding_id: int
    url: str
    platform: str | None
    created_alert: bool


def check_url(raw: str, rules: ProjectRules, cfg: TakedownConfig) -> tuple[str, str, str | None]:
    """规范化 URL，返回（URL、主机、平台 id）。官方域名、已知合法相似方与非公网 IP 不接受。"""
    url = normalize_url(raw)
    host = alert_host("url", url) if url else None
    if url is None or not host:
        raise SubmissionError("invalid url")
    literal = ip_literal(host)
    if literal is not None:
        if not ipaddress.ip_address(literal).is_global:
            raise SubmissionError("private or reserved address")
    elif protected_host(host, rules):
        raise SubmissionError("official or known lookalike domain")
    platform = cfg.platform_for(host)
    return url, host, platform.id if platform else None


def _floor(sub: Submission, previous: Finding | None) -> int:
    """分析员定过的最高级别对应的分数：之后的自动观测与再次提交都不能低于它。"""
    raw = (previous.match.get("manual") or {}).get("score") if previous is not None else None
    return max(SEVERITY_SCORES[sub.severity], raw if isinstance(raw, int) else 0)


def _score(sub: Submission, previous: Finding | None) -> Score:
    """分析员选定的级别；已有发现的分数更高时保留原分数（再次提交不降级）。"""
    manual = _floor(sub, previous)
    if previous is not None and previous.score > manual:
        return Score(
            previous.score,
            severity_for(previous.score),
            sub.category,
            dict(previous.score_breakdown),
        )
    return Score(manual, severity_for(manual), sub.category, {"manual": manual})


async def submit(
    session: AsyncSession,
    sub: Submission,
    *,
    rules: ProjectRules,
    cfg: TakedownConfig,
    user_id: int,
    now: datetime,
) -> SubmissionResult:
    if sub.category not in CATEGORIES or sub.severity not in SEVERITY_SCORES:
        raise SubmissionError("unsupported category or severity")
    description = sub.description.strip()
    if not description or len(description) > MAX_DESCRIPTION:
        raise SubmissionError("description is required (at most 2000 characters)")
    url, host, platform = check_url(sub.url, rules, cfg)
    manual: dict[str, object] = {
        "submitted_by": user_id,
        "description": description,
        "observed_at": sub.observed_at.isoformat() if sub.observed_at else None,
        "category": sub.category.value,  # 自动观测之后更新同一发现时仍以它为准
    }
    item = RawItem(
        connector_id=CONNECTOR_ID,
        source_item_id=uuid.uuid4().hex,
        fetched_at=now,
        url=url,
        payload={
            "url": url,
            "category": sub.category.value,
            "severity": sub.severity.value,
            "platform": platform,
            "manual": manual,
        },
        project_ids=(rules.project,),
    )
    await repo.upsert_project(session, rules)
    await repo.insert_raw_item(session, item)
    entity = await repo.upsert_entity(session, "url", url, now)
    previous = await session.scalar(
        select(Finding)
        .where(Finding.project_id == rules.project, Finding.entity_id == entity.id)
        .with_for_update()
    )
    score = _score(sub, previous)
    manual["score"] = _floor(sub, previous)
    # 合并已有的匹配信息（自动采集的原因等），再写入本次提交
    match = dict(previous.match) if previous is not None else {}
    reasons = [
        r
        for r in match.get("reasons", [])
        if isinstance(r, dict) and r.get("reason") != CONNECTOR_ID
    ]
    match.update(
        {
            "url": url,
            "platform": platform,
            "manual": manual,
            "reasons": [*reasons, {"reason": CONNECTOR_ID}],
        }
    )
    up = await repo.upsert_finding(
        session,
        project_id=rules.project,
        entity=entity,
        score=score,
        match=match,
        source=CONNECTOR_ID,
        now=now,
    )
    await repo.add_observation(session, up.finding, item, score.value, now)
    active = await session.scalar(
        select(Alert)
        .join(AlertFinding, AlertFinding.alert_id == Alert.id)
        .where(AlertFinding.finding_id == up.finding.id, Alert.status.in_(("open", "acknowledged")))
        .order_by(Alert.id.desc())
        .limit(1)
    )
    created = up.escalated or active is None
    if created:
        alert = await repo.open_alert(session, up.finding, score.severity, now)
        alert.assignee_id = user_id
        # open_alert 按类别决定是否取证；平台链接一律不让沙箱访问，其他链接任何级别都取证
        alert.evidence_status = "none" if platform else "pending"
    else:
        assert active is not None
        alert = active
        if platform is not None:
            if alert.evidence_status == "pending":  # 只撤销排队中的沙箱取证，保留已有证据状态
                alert.evidence_status = "none"
        elif alert.evidence_status in ("none", "failed"):
            alert.evidence_status = "pending"
            alert.evidence_attempts = 0
    if platform is None and ip_literal(host) is None:
        found = DomainMatcher(rules.domains).match(host)
        if found is not None and found.status == "match":  # 共享主机不命中品牌规则，不加监视
            await watchlist.ensure_watched(
                session, rules.project, found.domain, reason=CONNECTOR_ID, now=now
            )
    await session.flush()
    return SubmissionResult(alert.id, up.finding.id, url, platform, created)
