from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.metrics import MttdStat
from opti.core.scoring import Category, Score, Severity, severity_for
from opti.db import repo
from opti.db.models import Entity, Finding, RawItemRow
from opti.pipeline import metrics
from opti.sdk.models import RawItem

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 3, 8, tzinfo=UTC)


def _rdap(registered: datetime) -> dict[str, Any]:
    return {
        "rdap": {"data": {"registration": registered.isoformat()}, "fetched_at": NOW.isoformat()}
    }


async def _case(session: AsyncSession, rules: ProjectRules, domain: str, connector: str, payload: dict[str, Any],
                *, alerted: datetime | None, score: int = 70, enrichment: dict[str, Any] | None = None,
                category: Category = Category.TYPOSQUAT_DOMAIN) -> Finding:  # fmt: skip
    """建一个带观测的发现；alerted 为 None 时不开告警。"""
    when = alerted or NOW
    await repo.upsert_project(session, rules)
    item = RawItem(connector_id=connector, source_item_id=domain, fetched_at=when - timedelta(minutes=5), url=None,
                   payload=payload, project_ids=(rules.project,))  # fmt: skip
    await repo.insert_raw_item(session, item)
    entity = await repo.upsert_entity(session, "domain", domain, when)
    if enrichment is not None:
        entity.enrichment = enrichment
    s = Score(score, severity_for(score), category, {"base": score})
    up = await repo.upsert_finding(session, project_id=rules.project, entity=entity, score=s,
                                   match={"reasons": []}, source=connector, now=when)  # fmt: skip
    await repo.add_observation(session, up.finding, item, score, item.fetched_at)
    if alerted is not None:
        await repo.open_alert(session, up.finding, s.severity, alerted)
    return up.finding


async def test_mttd_by_source(
    session: AsyncSession, sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(metrics, "MTTD_QUERY_BATCH", 1)
    t1 = NOW - timedelta(days=1)
    await _case(session, sbr_rules, "sbr-a.top", "certstream", {"cert": {"seen": (t1 - timedelta(minutes=30)).timestamp()}},
                alerted=t1)  # fmt: skip
    escalated = await _case(session, sbr_rules, "sbr-b.top", "crtsh",
                            {"entry_timestamp": (t1 - timedelta(hours=2)).replace(tzinfo=None).isoformat()}, alerted=t1)  # fmt: skip
    await repo.open_alert(
        session, escalated, Severity.CRITICAL, t1 + timedelta(hours=5)
    )  # 升级：仍按第一条告警计
    await _case(session, sbr_rules, "sbr-c.top", "nrd", {"domain": "sbr-c.top"}, alerted=t1,
                enrichment=_rdap(t1 - timedelta(hours=20)))  # fmt: skip
    await _case(session, sbr_rules, "sbr-old.top", "certstream", {"cert": {"seen": (NOW - timedelta(days=40)).timestamp()}},
                alerted=NOW - timedelta(days=39))  # fmt: skip
    await _case(session, sbr_rules, "sbr-text.top", "certstream", {"cert": {"seen": (t1 - timedelta(hours=9)).timestamp()}},
                alerted=t1, category=Category.FRAUD_SCAM)  # 非域名类别不计  # fmt: skip
    await session.flush()
    stats = await metrics.mttd(
        session, sbr_rules.project, since=NOW - timedelta(days=30), until=NOW
    )
    assert stats == [MttdStat("ct", 2, 1.25, 0.5, 1.0), MttdStat("nrd", 1, 20.0, 1.0, 24.0)]


async def test_mttd_skips_missing_and_clamps(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    t1 = NOW - timedelta(hours=3)
    x = await _case(
        session, sbr_rules, "sbr-x.top", "certstream", {"cert": {}}, alerted=t1
    )  # 没有时间字段
    y = await _case(session, sbr_rules, "sbr-y.top", "nrd", {}, alerted=t1)  # 没有 RDAP 注册时间
    z = await _case(session, sbr_rules, "sbr-z.top", "certstream", {"cert": {"seen": (t1 + timedelta(minutes=2)).timestamp()}},
                    alerted=t1)  # 起点晚于告警（时钟偏差）  # fmt: skip
    assert (x.first_alerted_at, x.mttd_source, x.mttd_hours) == (t1, None, None)
    assert (y.mttd_source, y.mttd_hours) == (None, None)
    assert (z.mttd_source, z.mttd_hours) == ("ct", 0.0)
    stats = await metrics.mttd(session, sbr_rules.project, since=NOW - timedelta(days=1), until=NOW)
    assert stats == [MttdStat("ct", 1, 0.0, 1.0, 1.0), MttdStat("nrd", 0, None, None, 24.0)]


async def test_mttd_empty(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    stats = await metrics.mttd(session, sbr_rules.project, since=NOW - timedelta(days=1), until=NOW)
    assert stats == [MttdStat("ct", 0, None, None, 1.0), MttdStat("nrd", 0, None, None, 24.0)]


async def test_median_of_even_count_averages(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    t1 = NOW - timedelta(hours=10)
    for name, hours in (
        ("sbr-p.top", 0.5),
        ("sbr-q.top", 1.5),
        ("sbr-r.top", 2.0),
        ("sbr-s.top", 6.0),
    ):
        await _case(session, sbr_rules, name, "certstream", {"cert": {"seen": (t1 - timedelta(hours=hours)).timestamp()}},
                    alerted=t1)  # fmt: skip
    stats = await metrics.mttd(session, sbr_rules.project, since=NOW - timedelta(days=1), until=NOW)
    assert stats[0] == MttdStat("ct", 4, 1.75, 0.25, 1.0)


async def test_later_alert_fills_missing_sample(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    t1 = NOW - timedelta(hours=30)
    f = await _case(
        session, sbr_rules, "sbr-late.top", "nrd", {}, alerted=t1
    )  # 开告警时还没有 RDAP
    assert f.mttd_hours is None and f.first_alerted_at == t1
    e = await session.get(Entity, f.entity_id)
    assert e is not None
    e.enrichment = _rdap(t1 - timedelta(hours=6))
    await repo.open_alert(session, f, Severity.CRITICAL, NOW)  # 升级时补算，仍以第一条告警为准
    assert (f.first_alerted_at, f.mttd_source, f.mttd_hours) == (t1, "nrd", 6.0)


async def test_existing_sample_is_not_overwritten(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    t1 = NOW - timedelta(hours=30)
    f = await _case(
        session,
        sbr_rules,
        "sbr-keep.top",
        "nrd",
        {},
        alerted=t1,
        enrichment=_rdap(t1 - timedelta(hours=6)),
    )
    e = await session.get(Entity, f.entity_id)
    assert e is not None
    e.enrichment = _rdap(t1 - timedelta(hours=1))  # RDAP 刷新后变了
    await repo.open_alert(session, f, Severity.CRITICAL, NOW)
    assert (f.first_alerted_at, f.mttd_hours) == (t1, 6.0)


async def test_sample_survives_raw_item_purge(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    t1 = NOW - timedelta(hours=5)
    await _case(session, sbr_rules, "sbr-purged.top", "certstream", {"cert": {"seen": (t1 - timedelta(minutes=30)).timestamp()}},
                alerted=t1)  # fmt: skip
    await session.execute(delete(RawItemRow))  # 保留期清理原始数据
    stats = await metrics.mttd(session, sbr_rules.project, since=NOW - timedelta(days=1), until=NOW)
    assert stats[0] == MttdStat("ct", 1, 0.5, 1.0, 1.0)


async def test_backfill_samples(
    session: AsyncSession, sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(metrics, "MTTD_QUERY_BATCH", 2)
    t1 = NOW - timedelta(days=1)
    ct = await _case(session, sbr_rules, "sbr-a.top", "certstream", {"cert": {"seen": (t1 - timedelta(minutes=30)).timestamp()}},
                     alerted=t1)  # fmt: skip
    await repo.open_alert(session, ct, Severity.CRITICAL, t1 + timedelta(hours=5))
    nrd = await _case(
        session,
        sbr_rules,
        "sbr-c.top",
        "nrd",
        {},
        alerted=t1,
        enrichment=_rdap(t1 - timedelta(hours=20)),
    )
    other = await _case(
        session, sbr_rules, "sbr-o.top", "manual_submission", {}, alerted=t1
    )  # 来源不计
    quiet = await _case(
        session,
        sbr_rules,
        "sbr-q.top",
        "certstream",
        {"cert": {"seen": t1.timestamp()}},
        alerted=None,
    )
    for f in (ct, nrd, other):  # 模拟升级前的存量：只有告警，没有样本
        f.first_alerted_at = f.mttd_source = f.mttd_hours = None
    await session.flush()
    assert await metrics.backfill_samples(session) == 3
    assert (ct.first_alerted_at, ct.mttd_source, ct.mttd_hours) == (t1, "ct", 0.5)
    assert (nrd.first_alerted_at, nrd.mttd_source, nrd.mttd_hours) == (t1, "nrd", 20.0)
    assert (other.first_alerted_at, other.mttd_source, other.mttd_hours) == (t1, None, None)
    assert quiet.first_alerted_at is None  # 没有告警的不补
    assert await metrics.backfill_samples(session) == 0  # 可重复运行
