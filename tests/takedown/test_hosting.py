from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.core.config import ProjectRules
from opti.db.models import Entity
from opti.pipeline.enrichment import EnrichmentService
from opti.sdk.testing import make_context, static_enricher
from opti.takedown.hosting import (
    alert_host,
    host_ips,
    load_host_data,
    load_host_data_many,
    pending_entity_ids,
    prefetch,
)

pytestmark = pytest.mark.db
Seed = Callable[..., Awaitable[Any]]


def cached(data: dict[str, Any]) -> dict[str, Any]:
    """富化缓存条目（与 EnrichmentService 写入的格式一致）。"""
    return {"data": data, "fetched_at": datetime.now(UTC).isoformat()}


def _service(rules: ProjectRules) -> EnrichmentService:
    ctx = make_context(rules)
    return EnrichmentService(
        {
            "dns": static_enricher(ctx, "dns", {"exists": True, "a": ["104.16.1.1", "104.16.2.2"]}),
            "rdap": static_enricher(ctx, "rdap", {"registrar": "Cheap Registrar LLC"}),
            "ip_rdap": static_enricher(ctx, "ip_rdap", lambda ip: {"found": True, "network_name": f"NET-{ip}"}, types=("ip",)),
        }
    )  # fmt: skip


def test_alert_host_and_ips() -> None:
    assert alert_host("domain", "sbr-loans.com") == "sbr-loans.com"
    assert alert_host("url", "https://login.sbr-loans.com:8443/x?y=1") == "login.sbr-loans.com"
    assert alert_host("ip", "1.2.3.4") is None
    dns = {"a": ["9.9.9.9", "1.1.1.1"], "aaaa": ["2606:4700::1"]}
    assert host_ips(dns) == ["1.1.1.1", "9.9.9.9", "2606:4700::1"]
    assert host_ips({"a": [f"1.1.1.{i}" for i in range(9)]}) == ["1.1.1.0", "1.1.1.1", "1.1.1.2"]


async def test_prefetch_domain_url_and_ip_literal(
    session: AsyncSession, sbr_rules: ProjectRules, seed: Seed
) -> None:
    svc = _service(sbr_rules)
    now = datetime.now(UTC)
    s = await seed("sbr-loans.com")
    assert await prefetch(session, svc, s.entity, now) == ["104.16.1.1", "104.16.2.2"]
    data = await load_host_data(session, s.entity)
    assert data.host == "sbr-loans.com" and data.rdap == {"registrar": "Cheap Registrar LLC"}
    assert data.ips["104.16.1.1"] == {"found": True, "network_name": "NET-104.16.1.1"}

    u = await seed("https://login.sbr-pay.top/a", entity_type="url", category="phishing_site")
    assert await prefetch(session, svc, u.entity, now) == ["104.16.1.1", "104.16.2.2"]
    host = await session.scalar(
        select(Entity).where(Entity.type == "domain", Entity.value == "login.sbr-pay.top")
    )
    assert host is not None and "dns" in host.enrichment

    raw = await seed("http://203.0.113.9/sbr/login", entity_type="url", category="phishing_site")
    assert await prefetch(session, svc, raw.entity, now) == ["203.0.113.9"]
    assert (await load_host_data(session, raw.entity)).rdap is None


async def test_load_host_data_reports_missing_ips(session: AsyncSession, seed: Seed) -> None:
    s = await seed("sbr-loans.com", enrichment={"dns": cached({"a": ["104.16.9.9"]})})
    data = await load_host_data(session, s.entity)
    assert data.ips == {"104.16.9.9": None}  # 还没有 IP 的 RDAP 结果


async def test_load_host_data_many_matches_single(session: AsyncSession, seed: Seed) -> None:
    dom = await seed("sbr-loans.com", enrichment={
        "dns": cached({"a": ["104.16.1.1", "104.16.2.2"]}), "rdap": cached({"registrar": "R"}),
    })  # fmt: skip
    bare = await seed("sbr-bare.top")  # 没有 DNS 缓存
    url = await seed("https://login.sbr-pay.top/a", entity_type="url", category="phishing_site")
    host = await seed(
        "login.sbr-pay.top", enrichment={"dns": cached({"a": ["104.16.2.2", "104.16.3.3"]})}
    )
    lone = await seed(
        "https://sbr-lone.top/x", entity_type="url", category="phishing_site"
    )  # 主机没有域名实体
    raw = await seed("http://203.0.113.9/sbr", entity_type="url", category="phishing_site")
    ip = await seed("104.16.1.1", entity_type="ip", category="phishing_site")
    ip.entity.enrichment = {"ip_rdap": cached({"country": "NL", "network_name": "NET-A"})}
    await session.flush()
    entities = [
        dom.entity,
        bare.entity,
        url.entity,
        host.entity,
        lone.entity,
        raw.entity,
        ip.entity,
    ]
    many = await load_host_data_many(session, entities)
    assert many == {e.id: await load_host_data(session, e) for e in entities}
    assert many[url.entity.id].ips == {"104.16.2.2": None, "104.16.3.3": None}
    assert many[dom.entity.id].ips["104.16.1.1"] == {"country": "NL", "network_name": "NET-A"}
    assert await load_host_data_many(session, []) == {}


async def test_pending_entity_ids(session: AsyncSession, seed: Seed) -> None:
    high = await seed("sbr-loans.com", severity="high")
    await seed("sbr-loan.net", severity="medium")
    closed = await seed("sbr-credit.com", severity="critical")
    closed.alert.status = "closed"
    await session.flush()
    assert await pending_entity_ids(session, datetime.now(UTC), limit=10) == [high.entity.id]
