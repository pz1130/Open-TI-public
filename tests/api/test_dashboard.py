from datetime import timedelta
from typing import Any

import pytest

from opti.db import repo
from opti.db.models import Alert, Entity

pytestmark = pytest.mark.db


async def test_dashboard_api(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    high = await seed_alert("sbr-loans.com", severity="high")
    await seed_alert("sbr-portal.top", severity="medium")
    async with api.sessions.begin() as s:
        alert = await s.get(Alert, high.alert_id)
        assert alert is not None
        alert.created_at = api.clock() - timedelta(hours=30)  # High 的 SLA 是 24 小时：超期 6 小时
        dom = await s.get(Entity, high.entity_id)
        assert dom is not None
        dom.enrichment = {
            "dns": {"data": {"a": ["203.0.113.5"]}, "fetched_at": "2026-10-01T00:00:00Z"}
        }
        ip = await repo.upsert_entity(s, "ip", "203.0.113.5", api.clock())
        ip.enrichment = {"ip_rdap": {"data": {"country": "NL", "network_name": "EXAMPLE-NET"},
                                     "fetched_at": "2026-10-01T00:00:00Z"}}  # fmt: skip
    await make_user("vic", ("viewer",))
    await make_user("ops", ("platform_admin",))
    r = await (await login("vic")).get("/api/v1/dashboard", params={"days": 7})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["open_alerts"] == {"critical": 0, "high": 1, "medium": 1, "low": 0}
    assert d["new_alerts"] == 2 and d["new_findings"] == 2 and len(d["trend"]) == 8
    assert sum(day["high"] + day["medium"] for day in d["trend"]) == 2
    assert d["by_category"] == [{"name": "typosquat_domain", "count": 2}]
    assert d["by_source"] == [{"name": "certstream", "count": 2}]
    assert d["overdue"] == {"critical": 0, "high": 1, "medium": 0}
    assert (
        d["overdue_alerts"][0]["alert_id"] == high.alert_id
        and d["overdue_alerts"][0]["overdue_hours"] == 6.0
    )
    assert [a["subject"] for a in d["top_alerts"]] == ["sbr-loans.com", "sbr-portal.top"]
    assert d["hosting_countries"] == [{"name": "NL", "count": 1}]
    assert d["hosting_networks"] == [{"name": "EXAMPLE-NET", "count": 1}]
    assert [m["source"] for m in d["mttd"]] == ["ct", "nrd"] and d["mttr_hours"] is None
    assert (
        await (await login("ops")).get("/api/v1/dashboard")
    ).status_code == 403  # 平台管理员看不到告警内容


async def test_dashboard_empty(api: Any, make_user: Any, login: Any) -> None:
    await make_user("vic", ("viewer",))
    d = (await (await login("vic")).get("/api/v1/dashboard")).json()
    assert d["days"] == 30 and d["new_alerts"] == 0 and len(d["trend"]) == 31
    assert d["by_category"] == [] and d["top_alerts"] == [] and d["hosting_countries"] == []
    assert all(m["count"] == 0 and m["median_hours"] is None for m in d["mttd"])


async def test_dashboard_category_and_limit(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    await seed_alert("sbr-loans.com", severity="high")
    await seed_alert("sbr-portal.top", severity="medium")
    await seed_alert("sbr-pay.top", severity="medium", category="phishing_site")
    await make_user("vic", ("viewer",))
    client = await login("vic")
    d = (await client.get("/api/v1/dashboard", params={"category": "phishing_site"})).json()
    assert d["new_alerts"] == 1
    assert d["open_alerts"] == {"critical": 0, "high": 0, "medium": 1, "low": 0}
    assert d["by_category"] == [{"name": "phishing_site", "count": 1}]
    assert [a["subject"] for a in d["top_alerts"]] == ["sbr-pay.top"]
    assert sum(day["medium"] for day in d["trend"]) == 1
    # 发现数与来源贡献不受类别过滤
    assert d["new_findings"] == 3 and d["by_source"] == [{"name": "certstream", "count": 3}]
    d = (await client.get("/api/v1/dashboard", params={"limit": 1})).json()
    assert d["new_alerts"] == 3 and [a["subject"] for a in d["top_alerts"]] == ["sbr-loans.com"]
    assert (await client.get("/api/v1/dashboard", params={"limit": 51})).status_code == 422
