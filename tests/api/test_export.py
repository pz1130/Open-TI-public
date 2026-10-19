from datetime import timedelta
from typing import Any

import httpx
import pytest
import stix2
from sqlalchemy import select

from opti.api.tokens import create_token, revoke_token
from opti.db.models import Alert, ApiToken, AuditLog

pytestmark = pytest.mark.db
URL = "/api/v1/export/blocklist"
STIX = "/api/v1/export/stix"


async def test_blocklist_export_auth(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    a = await seed_alert("sbr-loans.com")
    async with api.sessions.begin() as s:
        (await s.get(Alert, a.alert_id)).triage_verdict = "true_positive"
        _, token = await create_token(
            s,
            name="dns-firewall",
            scopes=["blocklist:export"],
            days=30,
            actor="cli:test",
            now=api.clock(),
        )
        _, expired = await create_token(s, name="old", scopes=["blocklist:export"], days=1, actor="cli:test",
                                        now=api.clock() - timedelta(days=2))  # fmt: skip
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as raw:
        r = await raw.get(
            URL, params={"format": "rpz"}, headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200, r.text
        assert "sbr-loans.com CNAME ." in r.text
        assert r.headers["content-disposition"] == 'attachment; filename="opti-blocklist.rpz"'
        for bad in (f"Bearer {expired}", "Bearer opti_wrong", f"Basic {token}", "Bearer"):
            assert (await raw.get(URL, headers={"Authorization": bad})).status_code == 401, bad
        assert (await raw.get(URL)).status_code == 401  # 没有令牌也没有会话
    await make_user("alice", ("analyst",))
    await make_user("vic", ("viewer",))
    r = await (await login("alice")).get(URL, params={"format": "csv"})
    assert r.status_code == 200 and r.text.startswith("type,value")
    assert (await (await login("vic")).get(URL)).status_code == 403
    async with api.sessions() as s:
        actors = (
            await s.scalars(
                select(AuditLog.actor)
                .where(AuditLog.action == "export.blocklist")
                .order_by(AuditLog.id)
            )
        ).all()
        assert list(actors) == ["token:dns-firewall", "alice"]
        used = await s.scalar(select(ApiToken.last_used_at).where(ApiToken.name == "dns-firewall"))
        assert used is not None
    async with api.sessions.begin() as s:
        await revoke_token(s, "dns-firewall", api.clock())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as raw:
        assert (await raw.get(URL, headers={"Authorization": f"Bearer {token}"})).status_code == 401


async def test_stix_export(api: Any, make_user: Any, login: Any, seed_alert: Any) -> None:
    await seed_alert("sbr-loans.com")
    await seed_alert("sbr-portal.top", severity="low")
    async with api.sessions.begin() as s:
        _, token = await create_token(
            s, name="opencti", scopes=["stix:export"], days=30, actor="cli:test", now=api.clock()
        )
        _, blocklist_only = await create_token(
            s, name="dns", scopes=["blocklist:export"], days=30, actor="cli:test", now=api.clock()
        )
    auth = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as raw:
        r = await raw.get(STIX, headers=auth)
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("application/stix+json")
        assert r.headers["content-disposition"] == 'attachment; filename="opti-stix.json"'
        stix2.parse(r.text, allow_custom=False)
        patterns = [o["pattern"] for o in r.json()["objects"] if o["type"] == "indicator"]
        assert patterns == ["[domain-name:value = 'sbr-loans.com']"]
        r = await raw.get(STIX, params={"min_severity": "low"}, headers=auth)
        assert len([o for o in r.json()["objects"] if o["type"] == "indicator"]) == 2
        assert (
            await raw.get(STIX, headers={"Authorization": f"Bearer {blocklist_only}"})
        ).status_code == 401
    await make_user("vic", ("viewer",))
    await make_user("rita", ("responder",))
    assert (await (await login("vic")).get(STIX)).status_code == 403
    assert (await (await login("rita")).get(STIX)).status_code == 200
    async with api.sessions() as s:
        details = (
            await s.scalars(
                select(AuditLog.detail)
                .where(AuditLog.action == "export.stix")
                .order_by(AuditLog.id)
            )
        ).all()
    assert [d["findings"] for d in details] == [1, 2, 1]
