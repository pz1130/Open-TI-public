import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

from opti.api import config_store
from opti.configs import revisions
from opti.configs.projects import rules_text
from opti.core.domain_match import DomainMatcher
from opti.core.domains import to_ascii
from opti.db.models import AuditLog, ConfigRevision
from opti.pipeline import keyword_hits
from opti.pipeline.tasks import run_connector
from tests.api.conftest import ApiWorld, SeededAlert

pytestmark = pytest.mark.db
URL = "/api/v1/watchlist/keywords"


async def _client(make_user: Any, login: Any, username: str, *roles: str) -> httpx.AsyncClient:
    await make_user(username, roles)
    return await login(username)


def _with_broker(api: ApiWorld, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    api.deps.settings = replace(api.deps.settings, broker_url="redis://localhost:6379/0")
    queued: list[str] = []

    async def enqueue(cid: str) -> None:
        queued.append(cid)

    monkeypatch.setattr(run_connector, "kiq", enqueue)
    return queued


async def _actions(api: ApiWorld) -> list[tuple[str, dict[str, Any]]]:
    async with api.sessions() as s:
        rows = await s.execute(
            select(AuditLog.action, AuditLog.detail)
            .where(AuditLog.action.not_like("auth.%"))
            .order_by(AuditLog.id)
        )
    return [(a, d) for a, d in rows]


async def test_viewer_reads_keywords_with_stats(
    api: ApiWorld, make_user: Any, login: Any, seed_alert: Callable[..., Awaitable[SeededAlert]]
) -> None:
    await seed_alert()  # sbr-loans.com，命中 brand_label/sbr
    viewer = await _client(make_user, login, "vic", "viewer")
    r = await viewer.get(URL)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 0 and body["short_token_max_len"] == 4
    brand = {k["value"]: k for k in body["brand"]}
    assert brand["sbr"]["findings_30d"] == 1 and brand["sbr"]["last_seen"]
    assert brand["orbitbank"] == {"value": "orbitbank", "findings_30d": 0, "last_seen": None}
    assert body["restricted"][0]["value"] == "orbit" and "fund" in body["restricted"][0]["affixes"]
    assert [o["value"] for o in body["official"]] == ["sbr.int"]
    assert body["lookalike"] == ["sbrbank.com"]
    assert body["last_runs"] == {"crtsh": None, "dnstwist": None}
    assert (await viewer.post(URL, json={"kind": "brand", "value": "sbrx"})).status_code == 403
    assert (await viewer.post(f"{URL}/backfill")).status_code == 403


async def test_add_brand_saves_new_version_and_audits(
    api: ApiWorld, make_user: Any, login: Any
) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    r = await c.post(URL, json={"kind": "brand", "value": " SBRX "})
    assert r.status_code == 201, r.text
    assert r.json() == {
        "version": 1,
        "changed": True,
        "backfill": {
            "crtsh": {"status": "unavailable", "reason": "queue_unconfigured",
                      "next_allowed_at": None, "run_id": None},
            "dnstwist": {"status": "unavailable", "reason": "queue_unconfigured",
                         "next_allowed_at": None, "run_id": None},
        },
    }  # fmt: skip
    assert api.deps.rules.domains.brand_tokens[-1] == "sbrx"
    async with api.sessions() as s:
        rev = await revisions.latest(s, "rules")
    assert rev is not None and rev.note == "监视列表：新增品牌词 sbrx"
    assert await _actions(api) == [
        ("config.saved", {"kind": "rules", "version": 1, "digest": rev.digest}),
        ("watchlist.keyword_added", {"kind": "brand", "value": "sbrx", "version": 1}),
    ]
    again = await c.post(URL, json={"kind": "brand", "value": "sbrx"})
    assert again.json() == {"version": 1, "changed": False, "backfill": {}}
    async with api.sessions() as s:
        assert len((await s.scalars(select(ConfigRevision))).all()) == 1


async def test_errors(api: ApiWorld, make_user: Any, login: Any) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    cases = [
        ({"kind": "brand", "value": "a b"}, 422, "invalid_token"),
        ({"kind": "brand", "value": "orbit"}, 422, "token_conflict"),
        ({"kind": "official", "value": "not a domain"}, 422, "invalid_domain"),
        ({"kind": "lookalike", "value": "sbr.int"}, 422, "domain_conflict"),
        ({"kind": "restricted", "value": "silk", "affixes": []}, 422, "invalid_affix"),
    ]
    for body, status, reason in cases:
        r = await c.post(URL, json=body)
        assert (r.status_code, r.json()["detail"]) == (status, {"reason": reason}), body
    r = await c.delete(f"{URL}/brand/absent")
    assert (r.status_code, r.json()["detail"]) == (404, {"reason": "not_found"})
    r = await c.delete(f"{URL}/official/sbr.int")
    assert (r.status_code, r.json()["detail"]) == (422, {"reason": "last_item"})
    r = await c.put(f"{URL}/restricted/absent", json={"affixes": ["fund"]})
    assert r.status_code == 404
    assert (await c.delete(f"{URL}/nope/x")).status_code == 422


async def test_backfill_targets_depend_on_kind(
    api: ApiWorld, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    queued = _with_broker(api, monkeypatch)
    c = await _client(make_user, login, "alice", "analyst")
    r = await c.post(URL, json={"kind": "restricted", "value": "silk", "affixes": ["road"]})
    assert r.status_code == 201 and set(r.json()["backfill"]) == {"crtsh"}
    assert r.json()["backfill"]["crtsh"]["status"] == "queued" and queued == ["crtsh"]
    r = await c.post(URL, json={"kind": "lookalike", "value": "silkroad.com"})
    assert r.json()["changed"] is True and r.json()["backfill"] == {}
    r = await c.put(f"{URL}/restricted/silk", json={"affixes": ["road", "pay"]})
    assert r.status_code == 200 and api.deps.rules.domains.restricted_tokens["silk"] == (
        "road",
        "pay",
    )
    actions = [a for a in await _actions(api) if a[0].startswith("watchlist.")]
    assert actions[-1] == (
        "watchlist.keyword_updated",
        {"kind": "restricted", "value": "silk", "version": 3, "affixes": ["road", "pay"]},
    )
    r = await c.delete(f"{URL}/lookalike/silkroad.com")
    assert r.status_code == 200 and "silkroad.com" not in api.deps.rules.domains.known_lookalikes


async def test_version_conflict_is_retried(
    api: ApiWorld, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = config_store.store
    calls = 0

    async def flaky(*args: Any, **kwargs: Any) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise HTTPException(409, {"reason": "version_conflict", "current_version": 1})
        return await original(*args, **kwargs)

    monkeypatch.setattr(config_store, "store", flaky)
    c = await _client(make_user, login, "alice", "analyst")
    r = await c.post(URL, json={"kind": "brand", "value": "sbrx"})
    assert r.status_code == 201 and calls == 2


async def test_invalid_current_rules_block_edits(api: ApiWorld, make_user: Any, login: Any) -> None:
    async with api.sessions.begin() as s:
        await revisions.append(
            s, "rules", "project: [\n", base_version=0, user="x", note=None, now=api.clock()
        )
    c = await _client(make_user, login, "alice", "analyst")
    r = await c.post(URL, json={"kind": "brand", "value": "sbrx"})
    assert (r.status_code, r.json()["detail"]) == (409, {"reason": "rules_invalid"})


async def test_keyword_domains(
    api: ApiWorld, make_user: Any, login: Any, seed_alert: Callable[..., Awaitable[SeededAlert]]
) -> None:
    seeded = await seed_alert()
    viewer = await _client(make_user, login, "vic", "viewer")
    r = await viewer.get(f"{URL}/brand/SBR/domains")
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1
    item = r.json()["items"][0]
    assert item["domain"] == "sbr-loans.com" and item["alert_id"] == seeded.alert_id
    assert item["alert_status"] == "open" and item["severity"] == "high"
    assert (await viewer.get(f"{URL}/brand/orbitbank/domains")).json() == {
        "items": [],
        "total": 0,
    }
    assert (await viewer.get(f"{URL}/lookalike/sbrbank.com/domains")).status_code == 422


async def test_chinese_keyword_saved_in_config_can_list_hits_and_be_removed(
    api: ApiWorld, make_user: Any, login: Any, seed_alert: Callable[..., Awaitable[SeededAlert]]
) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    domains = api.rules.domains.model_copy(
        update={"brand_tokens": (*api.rules.domains.brand_tokens, "样本", "品牌")}
    )
    rules = api.rules.model_copy(update={"domains": domains})
    saved = await c.put("/api/v1/config/rules", json={"yaml": rules_text(rules), "base_version": 0})
    assert saved.status_code == 200, saved.text
    match = DomainMatcher(domains).match(to_ascii("样本-loans.com"))
    assert match is not None
    seeded = await seed_alert(domain=match.domain, match=match.to_dict())
    listing = await c.get(URL)
    stats = {row["value"]: row["findings_30d"] for row in listing.json()["brand"]}
    assert stats["样本"] == 1 and stats["品牌"] == 0
    response = await c.get(f"{URL}/brand/样本/domains")
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["domain"] == "样本-loans.com"
    assert response.json()["items"][0]["alert_id"] == seeded.alert_id
    empty = await c.get(f"{URL}/brand/品牌/domains")
    assert empty.status_code == 200 and empty.json() == {"items": [], "total": 0}
    removed = await c.delete(f"{URL}/brand/样本")
    assert removed.status_code == 200, removed.text
    assert "样本" not in api.deps.rules.domains.brand_tokens


@pytest.mark.parametrize("kind", ["brand", "restricted"])
async def test_chinese_keyword_watchlist_lifecycle(
    api: ApiWorld, make_user: Any, login: Any, kind: str
) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    response = await c.post(URL, json={"kind": kind, "value": "样本", "affixes": ["贷款"]})
    assert response.status_code == 201, response.text
    assert (await c.get(f"{URL}/{kind}/样本/domains")).status_code == 200
    if kind == "restricted":
        updated = await c.put(f"{URL}/restricted/样本", json={"affixes": ["银行"]})
        assert updated.status_code == 200, updated.text
    assert (await c.delete(f"{URL}/{kind}/样本")).status_code == 200


async def test_manual_backfill(
    api: ApiWorld, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = await _client(make_user, login, "alice", "analyst")
    assert (await c.post(f"{URL}/backfill")).status_code == 503
    queued = _with_broker(api, monkeypatch)
    r = await c.post(f"{URL}/backfill")
    assert r.status_code == 202
    assert {k: v["status"] for k, v in r.json().items()} == {
        "crtsh": "queued",
        "dnstwist": "queued",
    }
    assert queued == ["crtsh", "dnstwist"]
    assert (await _actions(api))[-1] == (
        "watchlist.backfill_requested",
        {"crtsh": "queued", "dnstwist": "queued"},
    )


async def test_stats_timeout_keeps_keyword_list(
    api: ApiWorld, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def slow(*args: Any, **kwargs: Any) -> None:
        raise DBAPIError("SELECT", {}, Exception("canceling statement due to statement timeout"))

    monkeypatch.setattr(keyword_hits, "stats", slow)
    viewer = await _client(make_user, login, "vic", "viewer")
    r = await viewer.get(URL)
    assert r.status_code == 200
    assert r.json()["brand"][0] == {"value": "sbr", "findings_30d": None, "last_seen": None}


async def test_save_response_and_audit_use_own_revision_even_if_another_save_finishes(
    api: ApiWorld, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = await _client(make_user, login, "alice", "analyst")
    second = await _client(make_user, login, "bob", "analyst")
    original = config_store.store

    async def interleaved(*args: Any, **kwargs: Any) -> bool:
        result = await original(*args, **kwargs)
        if kwargs.get("note") == "监视列表：新增品牌词 firstx":
            response = await second.post(URL, json={"kind": "brand", "value": "secondx"})
            assert response.status_code == 201 and response.json()["version"] == 2
        return result

    monkeypatch.setattr(config_store, "store", interleaved)
    response = await first.post(URL, json={"kind": "brand", "value": "firstx"})
    assert response.status_code == 201 and response.json()["version"] == 1
    saved = {
        detail["value"]: detail["version"]
        for action, detail in await _actions(api)
        if action == "watchlist.keyword_added"
    }
    assert saved == {"firstx": 1, "secondx": 2}
    assert {"firstx", "secondx"} <= set(api.deps.rules.domains.brand_tokens)


async def test_concurrent_keyword_saves_preserve_both_changes(
    api: ApiWorld, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = await _client(make_user, login, "alice", "analyst")
    second = await _client(make_user, login, "bob", "analyst")
    original = config_store.store
    ready = asyncio.Event()
    arrivals = 0
    calls = 0

    async def simultaneous(*args: Any, **kwargs: Any) -> bool:
        nonlocal arrivals, calls
        calls += 1
        if kwargs["base_version"] == 0:
            arrivals += 1
            if arrivals == 2:
                ready.set()
            await asyncio.wait_for(ready.wait(), timeout=5)
        return await original(*args, **kwargs)

    monkeypatch.setattr(config_store, "store", simultaneous)
    responses = await asyncio.gather(
        first.post(URL, json={"kind": "brand", "value": "firstx"}),
        second.post(URL, json={"kind": "brand", "value": "secondx"}),
    )
    assert [r.status_code for r in responses] == [201, 201]
    assert {r.json()["version"] for r in responses} == {1, 2}
    assert calls == 3  # One request retries against the revision saved by the other.
    assert {"firstx", "secondx"} <= set(api.deps.rules.domains.brand_tokens)
    saved = {
        detail["value"]: detail["version"]
        for action, detail in await _actions(api)
        if action == "watchlist.keyword_added"
    }
    assert saved == {
        "firstx": responses[0].json()["version"],
        "secondx": responses[1].json()["version"],
    }


async def test_removal_does_not_trigger_backfill(
    api: ApiWorld, make_user: Any, login: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 删词不需要回溯；若触发会占用最小间隔，挡住紧接着新增的词（crt.sh 1 小时、dnstwist 12 小时）
    queued = _with_broker(api, monkeypatch)
    c = await _client(make_user, login, "alice", "analyst")
    r = await c.delete(f"{URL}/brand/orbitbank")
    assert r.status_code == 200 and r.json()["changed"] is True
    assert r.json()["backfill"] == {} and queued == []
    r = await c.post(URL, json={"kind": "brand", "value": "sbrx"})
    assert {k: v["status"] for k, v in r.json()["backfill"].items()} == {
        "crtsh": "queued",
        "dnstwist": "queued",
    }
