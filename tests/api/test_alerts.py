from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select, update

from opti.core.scoring import Category, Score, Severity
from opti.db import repo
from opti.db.models import Alert, AuditLog, Entity, Evidence, Finding, SuppressionRule
from opti.pipeline import suppression
from opti.storage.artifacts import store_saver

pytestmark = pytest.mark.db
UserFactory = Callable[..., Awaitable[int]]


async def _evidence(api: Any, seeded: Any, kind: str, content_type: str, data: bytes) -> int:
    ref = await store_saver(api.store, node_id="hk1")(data, content_type)
    async with api.sessions.begin() as s:
        ev = Evidence(
            finding_id=seeded.finding_id, alert_id=seeded.alert_id, kind=kind, object_key=ref["key"],
            sha256=ref["sha256"], size=ref["size"], content_type=content_type, version_id=ref["version_id"],
            captured_at=api.clock(), node_id="hk1", method="opti-sandbox/test (chromium 140)",
            source_url="https://sbr-loans.com/",
        )  # fmt: skip
        s.add(ev)
        await s.flush()
        return ev.id


async def _actions(api: Any) -> list[str]:
    async with api.sessions() as s:
        return list((await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all())


async def test_queue_filters_and_pagination(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    high = await seed_alert("sbr-loans.com", "high")
    medium = await seed_alert("sbr-portal.top", "medium")
    critical = await seed_alert("sbr-grant.top", "critical", "phishing_site")
    c = await login()
    page = (await c.get("/api/v1/alerts")).json()
    assert [i["id"] for i in page["items"]] == [critical.alert_id, medium.alert_id, high.alert_id]
    first = page["items"][0]
    assert first["domain"] == "sbr-grant.top" and first["category"] == "phishing_site"
    assert first["reasons"] == ["brand_label"] and first["screenshot_id"] is None
    assert first["attack_techniques"][0]["id"] == "T1566"
    sev = (await c.get("/api/v1/alerts", params={"severity": ["high", "critical"]})).json()
    assert {i["id"] for i in sev["items"]} == {high.alert_id, critical.alert_id}
    q = (await c.get("/api/v1/alerts", params={"q": "PORTAL"})).json()
    assert [i["id"] for i in q["items"]] == [medium.alert_id]
    p1 = (await c.get("/api/v1/alerts", params={"limit": 2})).json()
    assert len(p1["items"]) == 2 and p1["next_cursor"] == medium.alert_id
    p2 = (await c.get("/api/v1/alerts", params={"limit": 2, "cursor": p1["next_cursor"]})).json()
    assert [i["id"] for i in p2["items"]] == [high.alert_id] and p2["next_cursor"] is None
    numbered = (await c.get("/api/v1/alerts", params={"page": 2, "limit": 2})).json()
    assert numbered["items"] == p2["items"] and numbered["total"] == 3
    filtered = (
        await c.get(
            "/api/v1/alerts", params={"page": 2, "limit": 1, "severity": ["high", "critical"]}
        )
    ).json()
    assert filtered["total"] == 2 and filtered["items"][0]["id"] == high.alert_id
    assert (
        await c.get("/api/v1/alerts", params={"page": 2, "cursor": p1["next_cursor"]})
    ).status_code == 422


async def test_detail_explains_and_is_audited(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    seeded = await seed_alert("sbr-loans.com", "high")
    shot = await _evidence(api, seeded, "screenshot", "image/png", b"\x89PNG demo")
    c = await login()
    d = (await c.get(f"/api/v1/alerts/{seeded.alert_id}")).json()
    assert d["alert"]["id"] == seeded.alert_id and d["alert"]["screenshot_id"] == shot
    assert d["alert"]["attack_techniques"][0]["id"] == "T1583.001"
    assert d["finding"]["score_breakdown"] == {"base": 20, "domain_risk": 50}
    assert d["finding"]["match"]["reasons"][0]["reason"] == "brand_label"
    assert [e["id"] for e in d["evidence"]] == [shot] and d["evidence"][0]["node_id"] == "hk1"
    assert d["feedback"] == [] and d["history"] == [] and d["watch"] is None
    assert "alert.view" in await _actions(api)
    assert (await c.get("/api/v1/alerts/999999")).status_code == 404


async def test_related_alerts_use_exact_fingerprints_and_project_scope(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    await make_user("vic", ("viewer",))
    target = await seed_alert("sbr-loans.com")
    related = await seed_alert("sbr-grants.top")
    weak = await seed_alert("sbr-payments.top")
    closed = await seed_alert("sbr-old.top")
    tls, icon = "a" * 64, "b" * 64
    async with api.sessions.begin() as s:
        for seeded, tls_hash, icon_hash in (
            (target, tls, icon),
            (related, tls, icon),
            (weak, "c" * 64, "d" * 64),
            (closed, tls, "e" * 64),
        ):
            entity = await s.get(Entity, seeded.entity_id)
            assert entity is not None
            entity.enrichment = {
                "tls": {"data": {"sha256": tls_hash}},
                "screenshot": {"data": {"favicon": {"hash": -12345, "sha256": icon_hash}}},
            }
        await s.execute(update(Alert).where(Alert.id == closed.alert_id).values(status="closed"))
        other_rules = api.rules.model_copy(update={"project": "other-project"})
        await repo.upsert_project(s, other_rules)
        other_entity = await s.get(Entity, related.entity_id)
        assert other_entity is not None
        other_finding = await repo.upsert_finding(
            s,
            project_id=other_rules.project,
            entity=other_entity,
            score=Score(
                70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"base": 20, "domain_risk": 50}
            ),
            match={},
            source="certstream",
            now=api.clock(),
        )
        await repo.open_alert(s, other_finding.finding, Severity.HIGH, api.clock())
    analyst = await login()
    detail = (await analyst.get(f"/api/v1/alerts/{target.alert_id}")).json()
    assert len(detail["related_alerts"]) == 1
    assert detail["related_alerts"][0]["id"] == related.alert_id
    assert detail["related_alerts"][0]["domain"] == "sbr-grants.top"
    assert detail["related_alerts"][0]["signals"] == ["tls_sha256", "favicon_sha256"]
    viewer = await login("vic")
    visible = (await viewer.get(f"/api/v1/alerts/{target.alert_id}")).json()
    assert visible["related_alerts"] == []


async def test_update_status_and_assignment(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    seeded = await seed_alert()
    c = await login()
    r = await c.patch(
        f"/api/v1/alerts/{seeded.alert_id}", json={"status": "acknowledged", "assign_to_me": True}
    )
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    d = (await c.get(f"/api/v1/alerts/{seeded.alert_id}")).json()
    assert d["assignee"] == "alice"
    assert (
        await c.patch(f"/api/v1/alerts/{seeded.alert_id}", json={"status": "superseded"})
    ).status_code == 422


async def test_list_assigned_to_me(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    await make_user("bob")
    mine = await seed_alert("sbr-loans.com")
    await seed_alert("sbr-portal.top")
    alice = await login()
    await alice.patch(f"/api/v1/alerts/{mine.alert_id}", json={"assign_to_me": True})
    page = (await alice.get("/api/v1/alerts", params={"assigned_to_me": "true"})).json()
    assert [a["id"] for a in page["items"]] == [mine.alert_id]
    assert len((await alice.get("/api/v1/alerts")).json()["items"]) == 2  # 默认不过滤
    bob = await login("bob")
    assert (await bob.get("/api/v1/alerts", params={"assigned_to_me": "true"})).json()[
        "items"
    ] == []


async def test_list_by_urgency(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    medium = await seed_alert("sbr-a.top", "medium")
    old_critical = await seed_alert("sbr-b.top", "critical")
    high = await seed_alert("sbr-c.top", "high")
    new_critical = await seed_alert("sbr-d.top", "critical")
    async with api.sessions.begin() as s:  # 先建的排在前面，与 id 顺序无关
        for seeded, hours in ((old_critical, 5), (new_critical, 1), (high, 3), (medium, 9)):
            alert = await s.get(Alert, seeded.alert_id)
            assert alert is not None
            alert.created_at = api.clock() - timedelta(hours=hours)
    c = await login()
    page = (await c.get("/api/v1/alerts", params={"order": "urgency", "limit": 3})).json()
    assert [a["id"] for a in page["items"]] == [
        old_critical.alert_id,
        new_critical.alert_id,
        high.alert_id,
    ]
    assert page["next_cursor"] is None  # 按紧急程度排序不分页
    r = await c.get("/api/v1/alerts", params={"order": "urgency", "cursor": 5})
    assert r.status_code == 422


async def test_superseded_alert_cannot_be_changed(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    old = await seed_alert("sbr-loans.com", "medium")
    new = await seed_alert("sbr-loans.com", "high")  # 同一 Finding 升级，旧告警被取代
    c = await login()
    assert (
        await c.patch(f"/api/v1/alerts/{old.alert_id}", json={"status": "closed"})
    ).status_code == 409
    d = (await c.get(f"/api/v1/alerts/{new.alert_id}")).json()
    assert [h["id"] for h in d["history"]] == [old.alert_id] and d["history"][0][
        "status"
    ] == "superseded"


async def test_false_positive_with_suppression(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    seeded = await seed_alert("login.sbr-loans.com", "high")
    sibling = await seed_alert("pay.sbr-loans.com", "medium")  # 同一可注册域下的另一条未结告警
    unrelated = await seed_alert("sbr-loans.top", "high")
    c = await login()
    body = {
        "verdict": "benign_known",
        "reason": "SBR Bank PLC 的合法子站",
        "suppress": "registered_domain",
        "suppress_days": 365,
    }
    r = await c.post(f"/api/v1/alerts/{seeded.alert_id}/feedback", json=body)
    assert r.status_code == 200
    assert r.json()["status"] == "closed" and r.json()["triage_verdict"] == "benign_known"
    async with api.sessions() as s:
        rule = (await s.scalars(select(SuppressionRule))).one()
        assert rule.kind == "registered_domain" and rule.value == "sbr-loans.com"
        assert rule.source_alert_id == seeded.alert_id and rule.expires_at is not None
        found = await suppression.find_active(
            s,
            api.rules.project,
            domain="www.sbr-loans.com",
            registered="sbr-loans.com",
            now=api.clock(),
        )
        assert found is not None
    d = (await c.get(f"/api/v1/alerts/{seeded.alert_id}")).json()
    assert d["feedback"][0]["verdict"] == "benign_known" and d["feedback"][0]["username"] == "alice"
    assert {"alert.feedback", "suppression.create"} <= set(await _actions(api))
    queue = {i["id"] for i in (await c.get("/api/v1/alerts")).json()["items"]}
    assert queue == {unrelated.alert_id}  # 规则覆盖的兄弟告警一并关闭，不再推送或截图
    sib = (await c.get(f"/api/v1/alerts/{sibling.alert_id}")).json()["alert"]
    assert sib["status"] == "closed" and sib["triage_verdict"] == "suppressed"


async def test_true_positive_acknowledges_and_cannot_suppress(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    seeded = await seed_alert()
    c = await login()
    bad = {"verdict": "true_positive", "suppress": "domain"}
    assert (await c.post(f"/api/v1/alerts/{seeded.alert_id}/feedback", json=bad)).status_code == 422
    ok = await c.post(
        f"/api/v1/alerts/{seeded.alert_id}/feedback", json={"verdict": "true_positive"}
    )
    assert ok.json()["status"] == "acknowledged"
    async with api.sessions() as s:
        assert (await s.scalars(select(SuppressionRule))).first() is None


async def test_viewer_cannot_triage_or_download_evidence(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user("vic", roles=("viewer",))
    await make_user("root", roles=("platform_admin",))
    seeded = await seed_alert()
    shot = await _evidence(api, seeded, "screenshot", "image/png", b"\x89PNG demo")
    async with api.sessions.begin() as s:
        entity = await s.get(Entity, seeded.entity_id)
        assert entity is not None
        entity.enrichment = {
            "screenshot": {
                "data": {"favicon": {"hash": -123456}, "visual": {"possible_matches": []}}
            },
            "http_probe": {"data": {"reachable": True}},
        }
    viewer = await login("vic")
    assert (await viewer.get("/api/v1/alerts")).status_code == 200
    detail = (await viewer.get(f"/api/v1/alerts/{seeded.alert_id}")).json()
    assert detail["enrichment"] == {"http_probe": {"data": {"reachable": True}}}
    assert (
        await viewer.post(
            f"/api/v1/alerts/{seeded.alert_id}/feedback", json={"verdict": "true_positive"}
        )
    ).status_code == 403
    assert (
        await viewer.patch(f"/api/v1/alerts/{seeded.alert_id}", json={"status": "closed"})
    ).status_code == 403
    assert (await viewer.get(f"/api/v1/evidence/{shot}/content")).status_code == 403
    await make_user("ana", roles=("analyst",))
    analyst = await login("ana")
    analyst_detail = (await analyst.get(f"/api/v1/alerts/{seeded.alert_id}")).json()
    assert "screenshot" in analyst_detail["enrichment"]
    admin = await login("root")
    assert (await admin.get("/api/v1/alerts")).status_code == 403  # 职责分离


async def test_html_snapshot_is_never_rendered(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    seeded = await seed_alert()
    png = await _evidence(api, seeded, "screenshot", "image/png", b"\x89PNG demo")
    html = await _evidence(api, seeded, "html", "text/html", b"<script>alert(1)</script>")
    c = await login()
    r = await c.get(f"/api/v1/evidence/{png}/content")
    assert r.headers["content-type"] == "image/png" and r.headers["content-disposition"].startswith(
        "inline"
    )
    r = await c.get(f"/api/v1/evidence/{html}/content")
    assert r.headers["content-type"].startswith("text/plain")
    assert r.headers["content-disposition"].startswith("attachment")
    assert r.headers["content-security-policy"].startswith("sandbox")
    assert r.content == b"<script>alert(1)</script>"
    assert (await _actions(api)).count("evidence.download") == 2


async def test_tampered_evidence_is_refused(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    await make_user()
    seeded = await seed_alert()
    ev_id = await _evidence(api, seeded, "screenshot", "image/png", b"\x89PNG demo")
    async with api.sessions() as s:
        key = (await s.get(Evidence, ev_id)).object_key  # type: ignore[union-attr]
    api.store.objects[key] = b"\x89PNG forged"
    c = await login()
    assert (await c.get(f"/api/v1/evidence/{ev_id}/content")).status_code == 409


async def test_requires_login(api: Any) -> None:
    import httpx

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app), base_url="http://testserver"
    ) as c:
        assert (await c.get("/api/v1/alerts")).status_code == 401


async def test_other_project_is_not_accessible(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    from opti.db import repo
    from opti.db.models import Alert, Finding

    await make_user()
    seeded = await seed_alert()
    shot = await _evidence(api, seeded, "screenshot", "image/png", b"\x89PNG demo")
    async with api.sessions.begin() as s:
        await repo.upsert_project(s, api.rules.model_copy(update={"project": "another"}))
        alert = await s.get(Alert, seeded.alert_id)
        finding = await s.get(Finding, seeded.finding_id)
        assert alert is not None and finding is not None
        alert.project_id = finding.project_id = "another"
    c = await login()
    assert (await c.get("/api/v1/alerts")).json()["items"] == []
    path = f"/api/v1/alerts/{seeded.alert_id}"
    assert (await c.get(path)).status_code == 404
    assert (await c.patch(path, json={"status": "closed"})).status_code == 404
    assert (await c.post(path + "/feedback", json={"verdict": "false_positive"})).status_code == 404
    assert (await c.get(f"/api/v1/evidence/{shot}/content")).status_code == 404


async def test_legacy_alert_uses_entity_domain(
    api: Any, make_user: UserFactory, login: Any, seed_alert: Any
) -> None:
    from opti.db.models import Alert

    await make_user()
    seeded = await seed_alert("sbr-loans.com")
    async with api.sessions.begin() as s:
        alert = await s.get(Alert, seeded.alert_id)
        assert alert is not None
        alert.routing = {}
    c = await login()
    r = await c.get("/api/v1/alerts", params={"q": "loans", "category": "typosquat_domain"})
    assert r.json()["items"][0]["domain"] == "sbr-loans.com"
    assert r.json()["items"][0]["attack_techniques"] == []
    assert (await c.get(f"/api/v1/alerts/{seeded.alert_id}")).json()["alert"][
        "domain"
    ] == "sbr-loans.com"


async def test_url_alert_detail_and_no_domain_suppression(
    api: Any, make_user: UserFactory, login: Any
) -> None:
    from opti.core.scoring import Category, Score, Severity
    from opti.db import repo

    await make_user()
    url = "https://sites.google.com/view/sbr-grants"
    async with api.sessions.begin() as s:
        await repo.upsert_project(s, api.rules)
        e = await repo.upsert_entity(s, "url", url, api.clock())
        up = await repo.upsert_finding(
            s, project_id=api.rules.project, entity=e,
            score=Score(75, Severity.HIGH, Category.PHISHING_SITE, {"base": 40, "url_brand": 15, "intel_hits": 20}),
            match={"url": url, "kind": "url", "reasons": [{"reason": "brand_path", "token": "sbr"}]},
            source="openphish", now=api.clock(),
        )  # fmt: skip
        alert_id = (await repo.open_alert(s, up.finding, Severity.HIGH, api.clock())).id
    c = await login()
    d = (await c.get(f"/api/v1/alerts/{alert_id}")).json()
    assert d["entity_type"] == "url" and d["alert"]["domain"] == url
    r = await c.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": "false_positive", "suppress": "domain"},
    )
    assert r.status_code == 422
    ok = await c.post(f"/api/v1/alerts/{alert_id}/feedback", json={"verdict": "false_positive"})
    assert ok.status_code == 200 and ok.json()["status"] == "closed"


async def test_ignore_preserves_alert_and_restores_only_on_important_change(
    api: Any,
    make_user: Any,
    login: Any,
    seed_alert: Any,
) -> None:
    await make_user()
    client = await login()
    seeded = await seed_alert()
    url = f"/api/v1/alerts/{seeded.alert_id}"
    async with api.sessions.begin() as s:
        entity = await s.get(Entity, seeded.entity_id)
        entity.enrichment = {
            "dns": {"data": {"a": ["8.8.8.8"]}},
            "http_probe": {
                "data": {
                    "title": "Welcome",
                    "status": 200,
                    "html_sha256": "before",
                    "has_password_field": False,
                }
            },
        }
    ignored = await client.patch(url, json={"ignored": True})
    assert (
        ignored.status_code == 200
        and ignored.json()["ignored"]
        and ignored.json()["status"] == "open"
    )
    baseline_time = ignored.json()["ignored_at"]
    assert (await client.get("/api/v1/alerts", params={"page": 1})).json()["total"] == 0
    only = (await client.get("/api/v1/alerts", params={"ignored": "only", "page": 1})).json()
    assert only["total"] == 1 and only["items"][0]["id"] == seeded.alert_id
    assert (await client.get("/api/v1/alerts", params={"ignored": "all"})).json()["items"][0][
        "ignored"
    ]
    assert (await client.get(url)).json()["alert"]["ignored"]  # 仍可访问详情

    async def scan(*, changed_title: bool = False, replacement: bool = False) -> None:
        async with api.sessions.begin() as s:
            entity = await s.get(Entity, seeded.entity_id)
            entity.enrichment = {
                "dns": {"data": {"a": ["8.8.8.8"]}, "fetched_at": "new"},
                "http_probe": {
                    "data": {
                        "title": "Apply for loan" if changed_title else "Welcome",
                        "status": 200,
                        "html_sha256": "after",
                        "has_password_field": False,
                    }
                },
                "screenshot": {"data": {"sha256": "random-screenshot"}},
            }
            finding = await s.get(Finding, seeded.finding_id)
            up = await repo.upsert_finding(
                s,
                project_id=api.rules.project,
                entity=entity,
                score=Score(70, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"content": 70}),
                match={**finding.match, "observed_at": api.clock().isoformat()},
                source="new_scan",
                now=api.clock(),
            )
            assert not up.escalated  # 相同级别的关键变化也能恢复
            if replacement:
                await repo.open_alert(s, up.finding, Severity.HIGH, api.clock())

    await scan()
    assert (await client.get(url)).json()["alert"]["ignored"]
    assert (await client.patch(url, json={"ignored": True})).json()["ignored_at"] == baseline_time
    await scan(changed_title=True)
    restored = (await client.get("/api/v1/alerts")).json()["items"][0]
    assert (
        restored["id"] == seeded.alert_id
        and not restored["ignored"]
        and restored["ignored_at"] is None
    )
    assert (await client.get("/api/v1/alerts", params={"ignored": "only"})).json()["items"] == []
    # 人工取消忽略也保留原记录。
    await client.patch(url, json={"ignored": True})
    await client.patch(url, json={"ignored": False})
    assert not (await client.get(url)).json()["alert"]["ignored"]
    # 同样的关键事实即使重开新记录，也沿用忽略。
    await scan()
    await client.patch(url, json={"ignored": True})
    await scan(replacement=True)
    active = (await client.get("/api/v1/alerts", params={"ignored": "only"})).json()["items"]
    assert len(active) == 1 and active[0]["id"] != seeded.alert_id
    assert (await client.get("/api/v1/alerts")).json()["items"] == []


async def test_ignore_requires_triage_and_rejects_closed_alert(
    api: Any,
    make_user: Any,
    login: Any,
    seed_alert: Any,
) -> None:
    await make_user()
    await make_user("vic", ("viewer",))
    analyst, viewer = await login(), await login("vic")
    seeded = await seed_alert()
    url = f"/api/v1/alerts/{seeded.alert_id}"
    assert (await viewer.patch(url, json={"ignored": True})).status_code == 403
    assert (await analyst.patch(url, json={"ignored": "yes"})).status_code == 422
    await analyst.patch(url, json={"status": "closed"})
    assert (await analyst.patch(url, json={"ignored": True})).status_code == 409
