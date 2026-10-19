"""STIX 导出的数据整理（设计文档 6.4、15）：近期发现 + 研判结论 + 观测次数 + 证据。

排除被研判为误报 / 已知无害 / 不在范围 / 重复的发现，以及官方域名与已知合法相似方（含子域）。
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Severity, severity_rank
from opti.core.stix import StixEvidence, StixFinding
from opti.db.models import Alert, AlertFinding, Entity, Evidence, Finding, FindingObservation
from opti.export.blocklist import protected_host

DISMISSED = frozenset({"false_positive", "benign_known", "out_of_scope", "duplicate"})
MAX_FINDINGS = 5000


def _host(entity_type: str, value: str) -> str | None:
    if entity_type == "domain":
        return value
    if entity_type == "url":
        return urlsplit(value).hostname
    return None


async def collect(
    session: AsyncSession,
    rules: ProjectRules,
    *,
    since: datetime,
    min_severity: Severity,
    limit: int = MAX_FINDINGS,
) -> list[StixFinding]:
    allowed = [s.value for s in Severity if severity_rank(s) >= severity_rank(min_severity)]
    rows = (
        await session.execute(
            select(Finding, Entity)
            .join(Entity, Entity.id == Finding.entity_id)
            .where(
                Finding.project_id == rules.project,
                Finding.last_seen >= since,
                Finding.severity.in_(allowed),
                # 自有证书到期是内部运维问题，不作为威胁情报外送（还会暴露内部主机名）
                Finding.category != Category.CERTIFICATE_EXPIRY,
            )
            .order_by(Finding.last_seen.desc(), Finding.id)
            .limit(limit)
        )
    ).all()
    ids = [f.id for f, _ in rows]
    if not ids:
        return []
    verdicts: dict[int, str | None] = {}
    latest_first = (
        select(AlertFinding.finding_id, Alert.triage_verdict)
        .join(Alert, Alert.id == AlertFinding.alert_id)
        .where(AlertFinding.finding_id.in_(ids))
        .order_by(AlertFinding.finding_id, Alert.id.desc())
    )
    for fid, verdict in (await session.execute(latest_first)).all():
        verdicts.setdefault(int(fid), verdict)  # 只取最近一次告警的研判结论
    counts = {
        int(fid): int(n)
        for fid, n in (
            await session.execute(
                select(FindingObservation.finding_id, func.count())
                .where(FindingObservation.finding_id.in_(ids))
                .group_by(FindingObservation.finding_id)
            )
        ).all()
    }
    evidence: dict[int, list[StixEvidence]] = defaultdict(list)
    for ev in await session.scalars(
        select(Evidence).where(Evidence.finding_id.in_(ids)).order_by(Evidence.id)
    ):
        if ev.finding_id is not None:
            evidence[ev.finding_id].append(StixEvidence(ev.id, ev.content_type, ev.sha256))
    out: list[StixFinding] = []
    for f, e in rows:
        verdict = verdicts.get(f.id)
        host = _host(e.type, e.value)
        if verdict in DISMISSED or (host and protected_host(host, rules)):
            continue
        out.append(
            StixFinding(
                finding_id=f.id, category=f.category, severity=f.severity, score=f.score, entity_type=e.type,
                entity_value=e.value, first_seen=f.first_seen, last_seen=f.last_seen,
                observations=counts.get(f.id, 0), confirmed=verdict == "true_positive", match=dict(f.match),
                evidence=tuple(evidence.get(f.id, ())),
            )
        )  # fmt: skip
    return out
