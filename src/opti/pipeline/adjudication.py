"""大模型研判的排队、执行与结果写回（设计文档 9.4；代码仓库密钥见设计 2026-10-17）。

处理器把灰区文本发现与扫出密钥的代码仓库发现放进队列并暂缓告警；后台任务在数据库事务之外调用模型，
再在短事务中写回：结论作为评分因子写入 Finding，必要时补开告警。多次失败、等待超时或研判关闭时，
按规则分数照常告警。
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from opti.core import policy
from opti.core.adjudication import (
    PROMPT_VERSION,
    AdjudicationError,
    LlmConfig,
    build_public_input,
)
from opti.core.code_adjudication import (
    CODE_CATEGORY,
    CODE_PROMPT_VERSION,
    CodeAssessment,
    CodeInput,
    build_code_input,
    select_secrets,
)
from opti.core.config import ProjectRules
from opti.core.scoring import (
    Category,
    Score,
    Severity,
    severity_for,
    severity_rank,
    with_code_llm,
    with_llm,
)
from opti.db import audit, repo
from opti.db.models import Adjudication, Document, Finding
from opti.llm import Adjudicator, Answer, Input
from opti.organization import Organization

LEASE = timedelta(minutes=5)
ACTOR = "system:llm"
log = logging.getLogger("opti.adjudication")


@dataclass(frozen=True)
class Claim:
    adjudication_id: int
    inp: Input


async def request(
    session: AsyncSession, finding: Finding, *, hold: Severity | None, now: datetime
) -> None:
    """为 Finding 排队研判；同一 Finding 只保留一条待处理请求。hold 为暂缓的告警级别。"""
    row = await session.scalar(
        select(Adjudication)
        .where(Adjudication.finding_id == finding.id, Adjudication.status == "pending")
        .limit(1)
        .with_for_update()
    )
    if row is None:
        session.add(
            Adjudication(
                finding_id=finding.id, status="pending", held_severity=hold.value if hold else None,
                attempts=0, created_at=now, updated_at=now,
            )
        )  # fmt: skip
    elif hold is not None and (
        row.held_severity is None
        or severity_rank(hold) > severity_rank(Severity(row.held_severity))
    ):
        row.held_severity, row.updated_at = hold.value, now
    await session.flush()


async def _summary(session: AsyncSession, match: Mapping[str, Any]) -> str:
    doc = match.get("document")
    doc_id = doc.get("id") if isinstance(doc, Mapping) else None
    if not isinstance(doc_id, int):
        return ""
    return await session.scalar(select(Document.snippet).where(Document.id == doc_id)) or ""


def _alert_from() -> Severity:
    return Severity(policy.current().risk.alert_from)


async def _release(session: AsyncSession, row: Adjudication, now: datetime) -> list[int]:
    """按 Finding 当前分数放行被暂缓的告警。"""
    if row.held_severity is None:
        return []
    finding = await session.get(Finding, row.finding_id)
    if finding is None or severity_rank(Severity(finding.severity)) < severity_rank(_alert_from()):
        return []
    return [(await repo.open_alert(session, finding, Severity(finding.severity), now)).id]


async def _fail(session: AsyncSession, row: Adjudication, error: str, now: datetime) -> list[int]:
    row.status, row.error, row.leased_until, row.updated_at = "failed", error[:500], None, now
    return await _release(session, row, now)


def _due(now: datetime) -> Any:
    return or_(Adjudication.leased_until.is_(None), Adjudication.leased_until < now)


async def expire(
    session: AsyncSession, *, cfg: LlmConfig | None, now: datetime, project_id: str | None = None
) -> list[int]:
    """等待超时的请求按规则放行；研判关闭（cfg 为 None）时立即放行全部排队请求。"""
    cutoff = now - timedelta(minutes=cfg.max_wait_minutes) if cfg is not None else now
    rows = (
        await session.scalars(
            select(Adjudication)
            .join(Finding, Finding.id == Adjudication.finding_id)
            .where(Adjudication.status == "pending", Adjudication.created_at <= cutoff, _due(now))
            .where(Finding.project_id == project_id if project_id is not None else true())
            .order_by(Adjudication.id)
            .with_for_update(of=Adjudication, skip_locked=True)
        )
    ).all()
    reason = "等待超时，按规则分数处理" if cfg is not None else "研判已关闭，按规则分数处理"
    alerts: list[int] = []
    for row in rows:
        alerts += await _fail(session, row, reason, now)
    return alerts


async def claim(
    session: AsyncSession,
    *,
    cfg: LlmConfig,
    adjudicator: Adjudicator,
    rules: ProjectRules,
    organization: Organization,
    now: datetime,
) -> tuple[list[Claim], list[int]]:
    rows = (
        await session.scalars(
            select(Adjudication)
            .join(Finding, Finding.id == Adjudication.finding_id)
            .where(Adjudication.status == "pending", _due(now), Finding.project_id == rules.project)
            .order_by(Adjudication.created_at, Adjudication.id)
            .limit(cfg.max_per_run)
            .with_for_update(of=Adjudication, skip_locked=True)
        )
    ).all()
    claims: list[Claim] = []
    released: list[int] = []
    for row in rows:
        finding = await session.get(Finding, row.finding_id)
        inp: Input
        try:
            if finding is None:
                raise AdjudicationError("发现已不存在")
            if finding.category == CODE_CATEGORY:
                if not cfg.code_enabled:
                    raise AdjudicationError("代码研判已关闭，按规则分数处理")
                inp = build_code_input(
                    finding.match, category=finding.category, rules=rules,
                    organization=organization.name, short_name=organization.short_name,
                )  # fmt: skip
            else:
                inp = build_public_input(
                    finding.match, category=finding.category, rules=rules, organization=organization.name,
                    short_name=organization.short_name, summary=await _summary(session, finding.match),
                )  # fmt: skip
        except AdjudicationError as e:
            released += await _fail(session, row, str(e), now)
            continue
        row.attempts += 1
        row.leased_until, row.updated_at, row.input_sha256 = now + LEASE, now, inp.digest()
        row.backend, row.model, row.prompt_version = (
            adjudicator.backend,
            adjudicator.model,
            CODE_PROMPT_VERSION if isinstance(inp, CodeInput) else PROMPT_VERSION,
        )
        claims.append(Claim(row.id, inp))
    return claims, released


async def apply(
    session: AsyncSession,
    adjudication_id: int,
    answer: Answer,
    *,
    now: datetime,
    refs: Mapping[str, str] | None = None,
) -> list[int]:
    """refs：代码研判的编号 → 密钥指纹（来自领取时构造的 CodeInput）。"""
    result, backend, model = answer.assessment, answer.backend, answer.model
    row = await session.get(Adjudication, adjudication_id, with_for_update=True)
    if row is None or row.status != "pending":
        return []
    finding = await session.get(Finding, row.finding_id, with_for_update=True)
    if finding is None:
        return await _fail(session, row, "发现已不存在", now)
    code = isinstance(result, CodeAssessment)
    if code and (finding.category != CODE_CATEGORY or refs is None):
        return await _fail(session, row, "发现已变化，按规则分数处理", now)
    if (
        code
        and refs is not None
        and set(refs.values()) != {str(x["fingerprint"]) for x in select_secrets(finding.match)}
    ):  # 研判途中重扫换了密钥：旧结论作废，放回队列按当前密钥重判
        row.leased_until, row.updated_at = None, now
        return []
    before = Severity(finding.severity)
    rule = {k: int(v) for k, v in finding.score_breakdown.items() if not k.startswith("llm")}
    value = max(0, min(100, sum(rule.values())))
    base = Score(value, severity_for(value), Category(finding.category), rule)
    version = CODE_PROMPT_VERSION if code else PROMPT_VERSION
    stamp = {"model": model, "prompt_version": version, "assessed_at": now.isoformat()}
    if isinstance(result, CodeAssessment):
        assert refs is not None
        score = with_code_llm(base, result.verdict, result.relation)
        secrets = [
            {"fingerprint": refs[ref], "verdict": v} for ref, v in result.secrets if ref in refs
        ]
        verdicts = {"llm_code": {**result.public(), "secrets": secrets, **stamp}}
    else:
        score = with_llm(base, result.verdict)
        verdicts = {"llm": {**result.public(), **stamp}}
    finding.score, finding.severity, finding.score_breakdown = (
        score.value,
        score.severity.value,
        score.breakdown,
    )
    finding.match = {**finding.match, **verdicts}
    row.status, row.verdict, row.output, row.error = "done", result.verdict, result.public(), None
    row.backend, row.model, row.prompt_version = backend, model, version
    row.leased_until, row.updated_at = None, now
    detail = {"backend": backend, "model": model, "prompt_version": version,
              "input_sha256": row.input_sha256, "verdict": result.verdict, "confidence": result.confidence,
              "provider": answer.provider}  # fmt: skip
    if isinstance(result, CodeAssessment):
        detail["relation"] = result.relation
    await audit.append(
        session, actor=ACTOR, action="llm.assess", now=now, target_type="finding",
        target_id=str(finding.id), detail=detail,
    )  # fmt: skip
    await session.flush()
    escalated = severity_rank(score.severity) > severity_rank(before)
    if severity_rank(score.severity) >= severity_rank(_alert_from()) and (
        row.held_severity is not None or escalated
    ):
        return [(await repo.open_alert(session, finding, score.severity, now)).id]
    return []


async def record_failure(
    session: AsyncSession,
    adjudication_id: int,
    error: str,
    *,
    cfg: LlmConfig,
    provider: str | None,
    now: datetime,
) -> list[int]:
    row = await session.get(Adjudication, adjudication_id, with_for_update=True)
    if row is None or row.status != "pending":
        return []
    await audit.append(
        session,
        actor=ACTOR,
        action="llm.assess_failed",
        now=now,
        target_type="finding",
        target_id=str(row.finding_id),
        detail={
            "backend": row.backend,
            "model": row.model,
            "prompt_version": row.prompt_version,
            "input_sha256": row.input_sha256,
            "attempt": row.attempts,
            "provider": provider,
        },
    )
    if row.attempts >= cfg.max_attempts:
        return await _fail(session, row, error, now)
    row.error, row.leased_until, row.updated_at = error[:500], None, now
    return []


async def run_pending(
    sessions: async_sessionmaker[AsyncSession],
    adjudicator: Adjudicator | None,
    *,
    cfg: LlmConfig | None,
    rules: ProjectRules,
    organization: Organization,
    clock: Callable[[], datetime],
) -> list[int]:
    """领取 → 事务外调用模型 → 逐条写回。返回新告警 ID。cfg 或 adjudicator 为 None 表示研判关闭。"""
    alerts: list[int] = []
    active = cfg if adjudicator is not None else None
    async with sessions() as s, s.begin():
        alerts += await expire(s, cfg=active, now=clock(), project_id=rules.project)
        claims, rejected = (
            await claim(
                s,
                cfg=active,
                adjudicator=adjudicator,
                rules=rules,
                organization=organization,
                now=clock(),
            )
            if active is not None and adjudicator is not None
            else ([], [])
        )
        alerts += rejected
    for c in claims:
        assert active is not None and adjudicator is not None
        try:
            answer = await adjudicator.answer(c.inp)
        except Exception as e:  # 后端任何错误只影响这一条（opti.llm 保证消息中不含密钥）
            log.warning("大模型研判失败（请求 %s）：%s", c.adjudication_id, type(e).__name__)
            error = str(e) if isinstance(e, AdjudicationError) else type(e).__name__
            async with sessions() as s, s.begin():
                alerts += await record_failure(s, c.adjudication_id, error, cfg=active,
                                               provider=adjudicator.provider, now=clock())  # fmt: skip
            continue
        refs = dict(c.inp.refs) if isinstance(c.inp, CodeInput) else None
        async with sessions() as s, s.begin():
            alerts += await apply(s, c.adjudication_id, answer, now=clock(), refs=refs)
    return alerts
