import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from opti.api.oidc.client import OidcClient
from opti.api.oidc.config import OidcConfig
from opti.api.oidc.testing import FakeIdp
from opti.api.throttle import SlidingWindow
from opti.sdk.testing import make_http

PASSWORD = "correct horse battery staple"
T = datetime(2026, 10, 3, tzinfo=UTC)


def test_sliding_window() -> None:
    w = SlidingWindow(3, timedelta(minutes=15), max_keys=2)
    for i in range(3):
        assert w.retry_after("a", T + timedelta(minutes=i)) is None
        w.hit("a", T + timedelta(minutes=i))
    assert w.retry_after("a", T + timedelta(minutes=3)) == 12 * 60  # 最早一次 + 15 分钟
    assert w.retry_after("a", T + timedelta(minutes=15, seconds=1)) is None  # 最早一次已滑出窗口
    w.hit("b", T)
    w.hit("c", T)  # 超过 max_keys：最久未用的 a 被淘汰，内存有上限
    assert len(w) == 2 and "a" not in w and "c" in w


def _client(api: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app),
        base_url="http://testserver",
        headers={"X-Requested-With": "opti"},
    )


@pytest.mark.db
async def test_failed_logins_throttled_by_ip(api: Any, make_user: Any) -> None:
    await make_user()
    async with _client(api) as c:
        for i in range(20):  # 每次换用户名：绕过按账号锁定，只剩按 IP 限流
            r = await c.post(
                "/api/v1/auth/login", json={"username": f"nobody{i}", "password": "wrong password!"}
            )
            assert r.status_code == 401
        r = await c.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        assert r.status_code == 429 and 0 < int(r.headers["Retry-After"]) <= 900
        api.clock.now += timedelta(minutes=16)
        assert (
            await c.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        ).status_code == 200


@pytest.mark.db
async def test_local_login_switch(api: Any, make_user: Any) -> None:
    await make_user()
    deps = api.app.state.deps
    deps.settings = dataclasses.replace(deps.settings, local_login=False)
    async with _client(api) as c:
        r = await c.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
        assert r.status_code == 403
        assert (await c.get("/api/v1/auth/providers")).json()["local"] is False


@pytest.mark.db
async def test_oidc_start_rate_limited(api: Any) -> None:
    idp = FakeIdp()
    cfg = OidcConfig(
        enabled=True, issuer=idp.issuer, client_id="opti", role_mapping={"viewer": ("v",)}
    )
    api.app.state.deps.oidc = OidcClient(
        cfg, make_http(idp.handler), None, redirect_uri="http://testserver/cb"
    )
    async with _client(api) as c:
        for _ in range(30):
            assert (await c.get("/api/v1/auth/oidc/start")).status_code == 303
        r = await c.get("/api/v1/auth/oidc/start")
        assert r.status_code == 429 and "Retry-After" in r.headers
