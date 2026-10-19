import json
from typing import Any

import pytest
from sqlalchemy import select

from opti.alerting.views import AlertView
from opti.core.exposure import breach_catalog, exposure_payload
from opti.db.models import Alert, AuditLog, ExposedAccount
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.http import HttpError
from opti.sdk.models import RawItem
from opti.tickets.client import PushResult

pytestmark = pytest.mark.db
LEAK = {"Name": "NewLeak", "Title": "New Leak 2026", "BreachDate": "2026-08-01", "DataClasses": ["Passwords"], "IsVerified": True}  # fmt: skip


class FakeTickets:
    name = "fake"

    def __init__(self) -> None:
        self.fail = False
        self.calls: list[tuple[AlertView, Any, str | None]] = []
        self.refs: list[str | None] = []

    async def push(
        self,
        view: AlertView,
        extra: Any = None,
        *,
        idempotency_key: str | None = None,
        existing_ref: str | None = None,
    ) -> PushResult:
        if self.fail:
            raise HttpError(view.link, 503, "down")
        self.calls.append((view, extra, idempotency_key))
        self.refs.append(existing_ref)
        return PushResult("IT-100", self.name)


async def _seed(api: Any, accounts: list[str], sid: str = "1") -> list[int]:
    domain = api.rules.domains.official[0]
    info = breach_catalog([LEAK])["NewLeak"]
    item = RawItem(
        connector_id="hibp", source_item_id=sid, fetched_at=api.clock(), url=None, project_ids=(api.rules.project,),
        payload=exposure_payload(source="hibp", kind="breach", key=f"hibp:{domain}:NewLeak", domain=domain, info=info,
                                 title=info.title, affected=len(accounts), accounts=accounts),
    )  # fmt: skip
    async with api.sessions.begin() as s:
        result = await Processor(api.rules, EnrichmentService({}), clock=api.clock).process(s, item)
    return result.alerts


def _emails(api: Any, *names: str) -> list[str]:
    return [f"{n}@{api.rules.domains.official[0]}" for n in names]


async def test_exposure_detail_has_no_emails(
    api: Any, make_user: Any, login: Any, seed_alert: Any
) -> None:
    [alert_id] = await _seed(api, _emails(api, "alice", "bob", "carol"))
    await make_user("alice", ("analyst",))
    c = await login("alice")
    r = await c.get(f"/api/v1/alerts/{alert_id}/exposure")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["title"] == "New Leak 2026" and body["affected"] == 3
    assert (
        body["accounts_total"] == 3 and body["accounts_pending"] == 3 and body["can_push"] is False
    )
    assert "@" not in json.dumps(body)
    other = await seed_alert("sbr-loans.com")
    assert (await c.get(f"/api/v1/alerts/{other.alert_id}/exposure")).status_code == 404


async def test_accounts_access_and_audit(api: Any, make_user: Any, login: Any) -> None:
    [alert_id] = await _seed(api, _emails(api, "alice", "bob"))
    await make_user("alice", ("analyst",))
    await make_user("rita", ("responder",))
    assert (
        await (await login("alice")).get(f"/api/v1/alerts/{alert_id}/exposure/accounts")
    ).status_code == 403
    r = await (await login("rita")).get(f"/api/v1/alerts/{alert_id}/exposure/accounts")
    assert r.status_code == 200 and [a["email"] for a in r.json()] == _emails(api, "alice", "bob")
    async with api.sessions() as s:
        row = (
            await s.scalars(select(AuditLog).where(AuditLog.action == "exposure.view_accounts"))
        ).one()
    assert row.actor == "rita" and row.detail == {"count": 2} and "@" not in json.dumps(row.detail)


async def test_push_only_pending_accounts(api: Any, make_user: Any, login: Any) -> None:
    [alert_id] = await _seed(api, _emails(api, "alice", "bob"))
    await make_user("alice", ("analyst",))
    c = await login("alice")
    url = f"/api/v1/alerts/{alert_id}/exposure/push"
    assert (await c.post(url)).status_code == 503  # 未配置工单通道
    fake = FakeTickets()
    api.app.state.deps.tickets = fake
    assert (await c.post(f"/api/v1/alerts/{alert_id}/ticket")).status_code == 409
    assert fake.calls == []
    r = await c.post(url)
    assert r.status_code == 200 and r.json() == {
        "pushed": 2,
        "channel": "fake",
        "ticket_ref": "IT-100",
    }
    _, extra, key = fake.calls[0]
    assert extra["exposure"]["accounts"] == _emails(api, "alice", "bob")
    assert extra["exposure"]["title"] == "New Leak 2026" and "多因素" in extra["exposure"]["advice"]
    assert key is not None and key.startswith(f"opti-alert-{alert_id}-accounts-")
    assert (await c.post(url)).status_code == 409  # 没有待推送的账户

    await _seed(api, _emails(api, "alice", "bob", "dave"), sid="2")  # 同一事件新增一个账户
    fake.fail = True
    assert (await c.post(url)).status_code == 502
    fake.fail = False
    r = await c.post(url)
    assert r.json()["pushed"] == 1 and fake.calls[-1][1]["exposure"]["accounts"] == _emails(
        api, "dave"
    )
    assert fake.refs == [None, "IT-100"]  # 第二批带上已有工单编号：Jira / ServiceNow 追加评论
    async with api.sessions() as s:
        alert = await s.get(Alert, alert_id)
        assert (
            alert is not None
            and alert.ticket_ref == "IT-100"
            and alert.ticket_pushed_at is not None
        )
        assert all(a.pushed_at is not None for a in (await s.scalars(select(ExposedAccount))).all())
        details = [
            r.detail
            for r in (
                await s.scalars(select(AuditLog).where(AuditLog.action == "exposure.push"))
            ).all()
        ]
    assert [d["count"] for d in details] == [2, 1] and "@" not in json.dumps(details)
