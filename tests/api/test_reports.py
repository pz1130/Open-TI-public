from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from opti.core.reports import empty_content
from opti.db import repo
from opti.db.models import Report

pytestmark = pytest.mark.db


async def _seed(api: Any) -> list[int]:
    ids = []
    async with api.sessions.begin() as s:
        await repo.upsert_project(s, api.rules)
        for i, kind in enumerate(["daily", "weekly", "daily"]):
            end = datetime(2026, 10, 1 + i, 1, tzinfo=UTC)
            start = end - timedelta(days=1 if kind == "daily" else 7)
            content = empty_content(kind, start=start, end=end)
            content["totals"]["findings"] = i
            content["alerts"] = [{"alert_id": 7, "severity": "medium", "category": "typosquat_domain",
                                  "subject": "sbr-loans.com", "score": 50}]  # fmt: skip
            row = Report(project_id=api.rules.project, kind=kind, period_start=start, period_end=end,
                         created_at=end, content=content, sent_sinks=[])  # fmt: skip
            s.add(row)
            await s.flush()
            ids.append(row.id)
    return ids


async def test_reports_api(api: Any, make_user: Any, login: Any) -> None:
    ids = await _seed(api)
    await make_user("vic", ("viewer",))
    await make_user("aud", ("auditor",))
    c = await login("vic")
    page = (await c.get("/api/v1/reports", params={"limit": 2})).json()
    assert [x["id"] for x in page["items"]] == [ids[2], ids[1]] and page["next_cursor"] == ids[1]
    assert (
        page["items"][0]["title"] == "威胁情报日报 2026-10-03"
        and page["items"][0]["totals"]["findings"] == 2
    )
    weekly = (await c.get("/api/v1/reports", params={"kind": "weekly"})).json()
    assert [x["id"] for x in weekly["items"]] == [ids[1]]
    numbered = (
        await c.get("/api/v1/reports", params={"page": 2, "limit": 1, "kind": "daily"})
    ).json()
    assert numbered["total"] == 2 and [r["id"] for r in numbered["items"]] == [ids[0]]
    detail = (await c.get(f"/api/v1/reports/{ids[0]}")).json()
    assert (
        detail["content"]["alerts"][0]["subject"] == "sbr-loans.com" and detail["sent_at"] is None
    )
    html = await c.get(f"/api/v1/reports/{ids[0]}/html")
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
    assert "attachment" in html.headers["content-disposition"]
    assert html.headers["content-security-policy"].startswith("sandbox")
    assert "sbr-loans[.]com" in html.text and "sbr-loans.com" not in html.text
    assert (await c.get("/api/v1/reports/999999")).status_code == 404
    assert (await (await login("aud")).get("/api/v1/reports")).status_code == 403


async def test_monthly_report_listed_as_monthly(api: Any, make_user: Any, login: Any) -> None:
    await _seed(api)
    start, end = datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 10, 1, tzinfo=UTC)
    async with api.sessions.begin() as s:
        row = Report(project_id=api.rules.project, kind="monthly", period_start=start, period_end=end,
                     created_at=end, content=empty_content("monthly", start=start, end=end), sent_sinks=[])  # fmt: skip
        s.add(row)
        await s.flush()
        monthly_id = row.id
    await make_user("vic", ("viewer",))
    c = await login("vic")
    page = (await c.get("/api/v1/reports", params={"kind": "monthly"})).json()
    assert [(x["id"], x["kind"], x["title"]) for x in page["items"]] == [
        (monthly_id, "monthly", "威胁情报月报 2026-09")
    ]
    detail = (await c.get(f"/api/v1/reports/{monthly_id}")).json()
    assert detail["kind"] == "monthly" and detail["content"]["trend"] == []
    html = await c.get(f"/api/v1/reports/{monthly_id}/html")
    # 以月份命名
    assert 'filename="report-monthly-2026-09.html"' in html.headers["content-disposition"]
