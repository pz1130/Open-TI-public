from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import async_sessionmaker

from opti.api.app import create_api
from opti.api.deps import ApiDeps
from opti.configs.runtime import ConfigRuntime
from opti.settings import Settings
from opti.storage.objects import MemoryObjectStore


def _client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def _app(sbr_rules: Any, web_dist: Path | None = None) -> Any:
    deps = ApiDeps(
        settings=Settings(cookie_secure=False),
        config=ConfigRuntime.static(sbr_rules),
        sessions=async_sessionmaker(),
        store=MemoryObjectStore(),
        web_dist=web_dist,
    )
    return create_api(deps)


async def test_security_headers_and_no_docs(sbr_rules: Any) -> None:
    async with _client(_app(sbr_rules)) as c:
        r = await c.get("/api/v1/auth/me")
        assert r.status_code == 401
        assert "default-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["cache-control"] == "no-store"
        assert len(r.headers["x-request-id"]) == 32
        for path in ("/docs", "/redoc", "/openapi.json", "/api/v1/openapi.json"):
            assert (await c.get(path)).status_code == 404


async def test_serves_single_page_app(sbr_rules: Any, tmp_path: Path) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    (tmp_path.parent / "secret.txt").write_text("nope")
    async with _client(_app(sbr_rules, tmp_path)) as c:
        assert "id=root" in (await c.get("/")).text
        assert "id=root" in (await c.get("/alerts/42")).text  # 前端路由
        assert (await c.get("/assets/app.js")).text == "console.log(1)"
        assert "nope" not in (await c.get("/..%2fsecret.txt")).text
        r = await c.get("/api/v1/nope")
        assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")


async def test_schema_routes_stay_disabled_with_web(sbr_rules: Any, tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    async with _client(_app(sbr_rules, tmp_path)) as c:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert (await c.get(path)).status_code == 404


async def test_spa_cache_headers(sbr_rules: Any, tmp_path: Path) -> None:
    """入口页每次向服务器确认，发布后立即拿到新的分块清单；带哈希的分块文件长期缓存。"""
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><div id=root></div>")
    (tmp_path / "assets" / "page-a1b2c3.js").write_text("console.log(1)")
    async with _client(_app(sbr_rules, tmp_path)) as c:
        for path in ("/", "/alerts/42"):
            assert (await c.get(path)).headers["cache-control"] == "no-cache"
        asset = await c.get("/assets/page-a1b2c3.js")
        assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
        missing = await c.get("/assets/page-old999.js")
        assert missing.status_code == 404
        assert "immutable" not in missing.headers.get("cache-control", "")
