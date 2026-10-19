import asyncio
from typing import Any

import httpx

from opti.sandbox.service import create_sandbox


async def _client(capture: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_sandbox(capture)), base_url="http://sb"
    )


async def test_capture_returns_result() -> None:
    async def capture(url: str, timeout: float) -> dict[str, Any]:
        return {"url": url, "final_url": url, "status": 200, "timeout": timeout}

    async with await _client(capture) as c:
        r = await c.post("/capture", json={"url": "https://sbr-loans.com/", "timeout": 5})
        assert r.status_code == 200 and r.json()["status"] == 200 and r.json()["timeout"] == 5
        assert (await c.get("/healthz")).json() == {"status": "ok"}


async def test_only_http_urls_and_bounded_timeout() -> None:
    async def capture(url: str, timeout: float) -> dict[str, Any]:
        raise AssertionError("不应调用")

    async with await _client(capture) as c:
        assert (await c.post("/capture", json={"url": "file:///etc/passwd"})).status_code == 422
        assert (await c.post("/capture", json={"url": "javascript:alert(1)"})).status_code == 422
        assert (
            await c.post("/capture", json={"url": "https://x.com/", "timeout": 600})
        ).status_code == 422


async def test_hung_capture_times_out(monkeypatch: Any) -> None:
    async def capture(url: str, timeout: float) -> dict[str, Any]:
        await asyncio.sleep(60)
        return {}

    monkeypatch.setattr("opti.sandbox.service.CAPTURE_GRACE", 0.1)
    async with await _client(capture) as c:
        r = await c.post("/capture", json={"url": "https://sbr-loans.com/", "timeout": 0.1})
    assert r.json() == {"url": "https://sbr-loans.com/", "error": "TimeoutError"}
