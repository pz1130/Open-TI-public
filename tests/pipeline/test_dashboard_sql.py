"""总览大盘改 SQL 聚合（设计 2026-10-11）：新实现与改造前的 Python 实现逐字段等价，且不再逐条载入告警。"""

import random
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity, severity_for
from opti.db import repo
from opti.db.models import Alert
from opti.pipeline import dashboard
from tests.pipeline.dashboard_reference import build as reference_build

pytestmark = pytest.mark.db
NOW = datetime(2026, 10, 11, 0, 30, tzinfo=UTC)  # 刚过 UTC 午夜：跨日界的告警落在不同的趋势日
CATEGORIES = [
    Category.TYPOSQUAT_DOMAIN,
    Category.PHISHING_SITE,
    Category.FRAUD_SCAM,
    Category.CLONE_SITE,
]
SOURCES = ["certstream", "crtsh", "nrd", "urlhaus", "manual_submission", "Zeta", "_x"]
SCORES = {"critical": 90, "high": 70, "medium": 50, "low": 30}


async def _seed(
    session: AsyncSession, rules: ProjectRules, *, n: int = 80, seed: int = 20261011
) -> None:
    """固定种子生成各种情形：级别、状态、改过类别、routing.score 形态、超期与否、多来源、跨日界、托管缓存。"""
    rng = random.Random(seed)
    await repo.upsert_project(session, rules)
    overdue_step = 0
    for i in range(n):
        severity = rng.choice(list(SCORES))
        kind = rng.choice(["domain", "domain", "url"])
        value = f"sbr-{i}.top" if kind == "domain" else f"https://login.sbr-{i}.top/p"
        entity = await repo.upsert_entity(session, kind, value, NOW)
        host = (
            await repo.upsert_entity(session, "domain", f"login.sbr-{i}.top", NOW)
            if kind == "url"
            else entity
        )
        if rng.random() < 0.6:
            ips = [f"203.0.113.{rng.randrange(1, 9)}" for _ in range(rng.randrange(1, 3))]
            host.enrichment = {"dns": {"data": {"a": ips}, "fetched_at": NOW.isoformat()}}
        points = SCORES[severity] + rng.randrange(0, 9)
        score = Score(points, severity_for(points), rng.choice(CATEGORIES), {"base": points})
        up = await repo.upsert_finding(session, project_id=rules.project, entity=entity, score=score,
                                       match={"domain": value, "reasons": []}, source=rng.choice(SOURCES), now=NOW)  # fmt: skip
        up.finding.sources = sorted(set(rng.sample(SOURCES, rng.randrange(0, 4))))
        up.finding.first_seen = NOW - timedelta(hours=rng.uniform(0, 2400))
        up.finding.last_seen = NOW - timedelta(hours=rng.uniform(0, 1200))
        for _ in range(rng.choice([1, 1, 2])):  # 第二条告警会把第一条置为 superseded
            alert = await repo.open_alert(session, up.finding, Severity(severity), NOW)
            alert.status = rng.choice(["open", "open", "acknowledged", "closed"])
            sla = dashboard.SLA_HOURS.get(severity)
            if alert.status in dashboard.ACTIVE and sla is not None and rng.random() < 0.5:
                overdue_step += (
                    1  # 超期时长两两相差 0.3 小时：参照实现按四舍五入后的值排序，避免并列
                )
                alert.created_at = NOW - timedelta(hours=sla + overdue_step * 0.3)
            elif i == 7:
                alert.created_at = NOW + timedelta(hours=2)  # 时钟偏差：未来时间的告警
            else:
                alert.created_at = NOW - timedelta(hours=rng.uniform(0, 2400), seconds=i)
            routing = dict(alert.routing)
            pick = rng.random()
            if pick < 0.2:
                routing["category"] = rng.choice(CATEGORIES).value  # 分析员改过类别
            elif pick < 0.3:
                routing["category"] = ""
            pick = rng.random()
            if pick < 0.15:
                routing["score"] = 99.5  # 非整数：退回发现的分数
            elif pick < 0.3:
                routing.pop("score", None)
            elif pick < 0.4:
                routing["score"] = rng.randrange(0, 100)
            alert.routing = routing
    for octet in range(1, 9):
        ip = await repo.upsert_entity(session, "ip", f"203.0.113.{octet}", NOW)
        ip.enrichment = {"ip_rdap": {"data": {"country": rng.choice(["NL", "US", "SG"]),
                                              "network_name": f"NET-{octet % 3}"}, "fetched_at": NOW.isoformat()}}  # fmt: skip
    await session.flush()


@pytest.mark.parametrize("days", [1, 7, 30, 90])
async def test_matches_reference(session: AsyncSession, sbr_rules: ProjectRules, days: int) -> None:
    await _seed(session, sbr_rules)
    for category in (None, "typosquat_domain", "phishing_site", "no_such_category"):
        for limit in (1, 5, 10):
            args: dict[str, Any] = {"now": NOW, "days": days, "category": category, "limit": limit}
            assert await dashboard.build(session, sbr_rules, **args) == await reference_build(
                session, sbr_rules, **args
            ), args


async def test_empty_matches_reference(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await repo.upsert_project(session, sbr_rules)
    args: dict[str, Any] = {"now": NOW, "days": 30}
    assert await dashboard.build(session, sbr_rules, **args) == await reference_build(
        session, sbr_rules, **args
    )


async def test_loads_only_limited_alerts(session: AsyncSession, sbr_rules: ProjectRules) -> None:
    await _seed(session, sbr_rules, n=60)
    session.expunge_all()
    loaded: list[object] = []
    event.listen(session.sync_session, "loaded_as_persistent", lambda _s, obj: loaded.append(obj))
    await dashboard.build(session, sbr_rules, now=NOW, days=90, limit=3)
    alerts = [o for o in loaded if isinstance(o, Alert)]
    assert len(alerts) <= 6  # 只有超期与 Top 两个列表各取 limit 条


async def test_hosting_uses_newest_hosts(
    session: AsyncSession, sbr_rules: ProjectRules, monkeypatch: pytest.MonkeyPatch
) -> None:
    """主机超过 MAX_HOSTING 时取最新告警的主机（原先取数据库无序返回的前几个）。"""
    monkeypatch.setattr(dashboard, "MAX_HOSTING", 1)
    await repo.upsert_project(session, sbr_rules)
    for name, octet, country, age in (("sbr-old.top", 1, "US", 5), ("sbr-new.top", 2, "NL", 1)):
        entity = await repo.upsert_entity(session, "domain", name, NOW)
        entity.enrichment = {
            "dns": {"data": {"a": [f"203.0.113.{octet}"]}, "fetched_at": NOW.isoformat()}
        }
        ip = await repo.upsert_entity(session, "ip", f"203.0.113.{octet}", NOW)
        ip.enrichment = {"ip_rdap": {"data": {"country": country}, "fetched_at": NOW.isoformat()}}
        score = Score(70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"base": 70})
        up = await repo.upsert_finding(session, project_id=sbr_rules.project, entity=entity, score=score,
                                       match={"domain": name, "reasons": []}, source="certstream", now=NOW)  # fmt: skip
        alert = await repo.open_alert(session, up.finding, Severity.HIGH, NOW)
        alert.created_at = NOW - timedelta(hours=age)
    await session.flush()
    d = await dashboard.build(session, sbr_rules, now=NOW, days=7)
    assert d["hosting_countries"] == [{"name": "NL", "count": 1}]
