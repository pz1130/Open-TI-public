import hashlib
import hmac
import json
from typing import Any

import httpx
import pytest

from opti.core.config import ProjectRules
from opti.intake.app import GIF, IntakeDeps, create_intake
from opti.sdk.models import RawItem

TOKEN = "c" * 32
KEY = b"k" * 32


class Clock:
    def __init__(self) -> None:
        self.now = 1_790_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def world(sbr_rules: ProjectRules) -> tuple[httpx.AsyncClient, list[RawItem], Clock]:
    sent: list[RawItem] = []
    clock = Clock()

    async def forward(item: RawItem) -> None:
        sent.append(item)

    deps = IntakeDeps(
        rules=sbr_rules, forward=forward, canary_token=TOKEN, report_key=KEY, clock=clock
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_intake(deps)), base_url="https://www.example.org"
    )
    return client, sent, clock


async def test_canary_js_and_css(world: Any) -> None:
    c, sent, _ = world
    r = await c.get(
        f"/ti-intake/b/{TOKEN}.gif", params={"v": "js", "h": "Secure-Online-Banking.top"}
    )
    assert r.status_code == 200 and r.content == GIF and r.headers["cache-control"] == "no-store"
    r = await c.get(
        f"/ti-intake/b/{TOKEN}.gif",
        params={"v": "css"},
        headers={"Referer": "https://clone-two.top/"},
    )
    assert [i.payload["indicators"][0]["value"] for i in sent] == [
        "secure-online-banking.top",
        "clone-two.top",
    ]
    first = sent[0]
    assert first.connector_id == "canary" and first.payload["signal"] == "canary"
    assert first.payload["intel"] == {"source": "canary", "confirmed": True}
    assert first.payload["context"]["variant"] == "js"
    assert first.source_item_id == "secure-online-banking.top:2026092114"


async def test_canary_rate_limit_and_token_oracle(world: Any) -> None:
    c, sent, clock = world
    bad = await c.get("/ti-intake/b/wrong.gif", params={"h": "clone.top"})
    assert bad.status_code == 200 and bad.content == GIF  # 与正确令牌的响应完全相同
    for _ in range(5):
        await c.get(f"/ti-intake/b/{TOKEN}.gif", params={"h": "clone.top"})
    clock.now += 601
    await c.get(f"/ti-intake/b/{TOKEN}.gif", params={"h": "clone.top"})
    assert len(sent) == 2


async def test_canary_ignores_official_and_garbage(world: Any) -> None:
    c, sent, _ = world
    for host in ("sbr.int", "www.sbr.int", "localhost", "10.0.0.1", "", "a" * 300):
        await c.get(f"/ti-intake/b/{TOKEN}.gif", params={"h": host})
    await c.get(f"/ti-intake/b/{TOKEN}.gif", params={"v": "css"})  # 没有 Referer
    assert sent == []


def _signed(body: dict[str, Any], ts: int, key: bytes = KEY) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body).encode()
    sig = hmac.new(key, f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
    return raw, {
        "X-Opti-Timestamp": str(ts),
        "X-Opti-Signature": sig,
        "Content-Type": "application/json",
    }


async def test_report_signature_and_replay(world: Any) -> None:
    c, sent, clock = world
    report = {"description": "有人自称 Sample Brand 员工，要求先交手续费", "urls": ["https://loan-sbr.top/apply"],
              "contact": "tel:+86-000", "category": "loan"}  # fmt: skip
    raw, headers = _signed(report, int(clock.now))
    r = await c.post("/ti-intake/report", content=raw, headers=headers)
    assert r.status_code == 202 and len(r.json()["id"]) == 32
    item = sent[0]
    assert item.connector_id == "public_report" and item.payload["signal"] == "reported"
    assert item.payload["indicators"][0] == {"type": "report", "value": r.json()["id"]}
    assert {"type": "url", "value": "https://loan-sbr.top/apply"} in item.payload["indicators"]
    assert (
        item.payload["context"]["brand_mentioned"] is True
        and item.payload["context"]["contact"] == "tel:+86-000"
    )
    assert (await c.post("/ti-intake/report", content=raw, headers=headers)).status_code == 409
    raw2, h2 = _signed(report, int(clock.now) - 301)
    assert (await c.post("/ti-intake/report", content=raw2, headers=h2)).status_code == 401
    raw3, h3 = _signed(report, int(clock.now), key=b"x" * 32)
    assert (await c.post("/ti-intake/report", content=raw3, headers=h3)).status_code == 401
    assert (await c.post("/ti-intake/report", content=raw)).status_code == 401
    big, hb = _signed({"description": "x" * 70_000}, int(clock.now))
    assert (await c.post("/ti-intake/report", content=big, headers=hb)).status_code == 413
    bad, hbad = _signed({"description": ""}, int(clock.now))
    assert (await c.post("/ti-intake/report", content=bad, headers=hbad)).status_code == 422
    assert len(sent) == 1


async def test_only_intake_paths_exist(world: Any) -> None:
    c, _, _ = world
    assert (await c.get("/ti-intake/healthz")).json() == {"status": "ok"}
    for path in ("/", "/docs", "/openapi.json", "/api/v1/alerts"):
        assert (await c.get(path)).status_code == 404


async def test_chunked_oversized_and_malformed_headers(world: Any) -> None:
    c, sent, clock = world

    async def chunks():
        for _ in range(70):
            yield b"x" * 1024

    assert (await c.post("/ti-intake/report", content=chunks())).status_code == 413
    raw, headers = _signed({"description": "report"}, int(clock.now))
    headers["X-Opti-Signature"] = "bad-signature"
    assert (await c.post("/ti-intake/report", content=raw, headers=headers)).status_code == 401
    headers["X-Opti-Timestamp"] = "1" * 10000
    assert (await c.post("/ti-intake/report", content=raw, headers=headers)).status_code == 401
    assert sent == []


async def test_forward_failure_is_retryable_and_beacon_stays_gif(sbr_rules: ProjectRules) -> None:
    attempts = 0

    async def forward(item: RawItem) -> None:
        nonlocal attempts
        attempts += 1
        if attempts in (1, 3):
            raise RuntimeError("queue unavailable")

    clock = Clock()
    app = create_intake(IntakeDeps(sbr_rules, forward, TOKEN, KEY, clock=clock))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://example.org"
    ) as c:
        for _ in range(2):
            response = await c.get(f"/ti-intake/b/{TOKEN}.gif?h=clone.top")
            assert response.status_code == 200 and response.content == GIF
        raw, headers = _signed({"description": "report"}, int(clock.now))
        assert (await c.post("/ti-intake/report", content=raw, headers=headers)).status_code == 503
        assert (await c.post("/ti-intake/report", content=raw, headers=headers)).status_code == 202
    assert attempts == 4


async def test_concurrent_report_replay(world: Any) -> None:
    import asyncio

    c, sent, clock = world
    raw, headers = _signed({"description": "report"}, int(clock.now))
    responses = await asyncio.gather(
        *(c.post("/ti-intake/report", content=raw, headers=headers) for _ in range(5))
    )
    assert sorted(r.status_code for r in responses) == [202, 409, 409, 409, 409]
    assert len(sent) == 1


async def test_malformed_css_referer_and_overlong_hostname(world: Any) -> None:
    c, sent, _ = world
    for params, headers in [
        ({"v": "css"}, {"referer": "http://[bad"}),
        ({"h": "x." * 130 + "top"}, {}),
    ]:
        response = await c.get(f"/ti-intake/b/{TOKEN}.gif", params=params, headers=headers)
        assert response.status_code == 200 and response.content == GIF
    assert sent == []


async def test_intake_uses_refreshed_project(sbr_rules: ProjectRules) -> None:
    from opti.configs.edge import EdgeRules

    sent: list[RawItem] = []

    async def forward(item: RawItem) -> None:
        sent.append(item)

    async def fetch():  # type: ignore[no-untyped-def]
        return 1, "d1", sbr_rules.model_copy(update={"project": "next"}).model_dump(mode="json")

    edge = EdgeRules(sbr_rules, fetch, process="intake@t")
    deps = IntakeDeps(rules=sbr_rules, forward=forward, canary_token=TOKEN, report_key=KEY,
                      clock=Clock(), edge=edge)  # fmt: skip
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_intake(deps)), base_url="https://www.example.org"
    ) as c:
        await edge.refresh()
        await c.get(f"/ti-intake/b/{TOKEN}.gif", params={"v": "js", "h": "clone-three.top"})
    assert [i.project_ids for i in sent] == [("next",)]
