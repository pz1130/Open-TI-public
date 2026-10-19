"""URL feed → actual HTTP probe/Chromium evidence → analyst UI, using a controlled page."""

import asyncio
import socket
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import httpx
import pytest
import uvicorn
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.api import security
from opti.api.app import create_api
from opti.api.deps import ApiDeps
from opti.configs.runtime import ConfigRuntime
from opti.connectors.openphish.connector import OpenPhishConnector
from opti.core.config import ProjectRules
from opti.db import audit
from opti.db.engine import make_sessionmaker
from opti.db.models import Alert, Entity, Evidence, Finding, SuppressionRule, WatchedDomain
from opti.enrichers.http_probe.enricher import HttpProbeEnricher
from opti.enrichers.screenshot.enricher import ScreenshotEnricher
from opti.pipeline import evidence
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sandbox.service import PlaywrightCapture, create_sandbox
from opti.sdk.context import ConnectorContext, EnvSecretProvider
from opti.sdk.http import RateLimitedHttpClient
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context
from opti.settings import Settings
from opti.storage.artifacts import store_saver
from opti.storage.objects import MemoryObjectStore

pytestmark = [pytest.mark.db, pytest.mark.browser]
playwright_api = pytest.importorskip("playwright.async_api")
DIST = Path(__file__).resolve().parents[2] / "web" / "dist"
TARGET = "/sbr-grants/login?x=7"
PASSWORD = "correct horse battery staple"


async def test_url_feed_to_real_evidence_and_triage(
    clean_db: str, sbr_rules: ProjectRules, tmp_path: Path
) -> None:
    if not (DIST / "index.html").exists():
        pytest.skip("先构建前端：pnpm -C web run build")
    requests: list[str] = []

    class Page(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            if self.path != TARGET:
                self.send_error(404)
                return
            html = b'<title>Sample Brand grants</title><h1>Sample Brand</h1><form><input type="password"></form>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html)

        def log_message(self, format: str, *args: object) -> None:
            pass

    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Page)
    thread = Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{fixture.server_port}{TARGET}"
    connector = OpenPhishConnector(
        make_context(
            sbr_rules,
            connector_id="openphish",
            handler=lambda _r: httpx.Response(200, text=f"{url}\nhttps://sbr.int/sbr"),
        ),
        {},
    )
    probe_http = RateLimitedHttpClient(transport=httpx.AsyncHTTPTransport())
    sandbox_http = RateLimitedHttpClient(
        transport=httpx.ASGITransport(app=create_sandbox(PlaywrightCapture(allow_private=True)))
    )
    secrets = EnvSecretProvider({})
    probe = HttpProbeEnricher(
        ConnectorContext("http_probe", sbr_rules, probe_http, secrets=secrets),
        {"allow_private_targets": True},  # Test fixture only; production guards stay enabled.
    )
    screenshot = ScreenshotEnricher(
        ConnectorContext("screenshot", sbr_rules, sandbox_http, secrets=secrets),
        {"sandbox_url": "http://sandbox", "timeout": 10},
    )
    store = MemoryObjectStore()
    service = EnrichmentService(
        {"http_probe": probe, "screenshot": screenshot}, saver=store_saver(store)
    )
    processor = Processor(sbr_rules, service)
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    server: uvicorn.Server | None = None
    task: asyncio.Task[None] | None = None
    try:
        items = [i async for i in connector.fetch(build_query_plan(sbr_rules))]
        assert len(items) == 1 and items[0].payload["feed_url"] == url
        async with sessions.begin() as session:
            await security.create_user(
                session,
                username="url-analyst",
                password=PASSWORD,
                roles=["analyst"],
                now=datetime.now(UTC),
            )
            result = await processor.process(session, items[0])
            alert_id = result.alerts[0]
        async with sessions.begin() as session:
            alert = await session.get(Alert, alert_id)
            assert alert is not None and alert.severity == "critical"
            assert await evidence.capture(session, alert, service, datetime.now(UTC))
            finding = (await session.scalars(select(Finding))).one()
            entity = (await session.scalars(select(Entity))).one()
            assert (entity.type, entity.value, finding.category) == ("url", url, "phishing_site")
            assert finding.score_breakdown["intel_hits"] == 20
            rows = (await session.scalars(select(Evidence))).all()
            assert {row.kind for row in rows} == {"screenshot", "html"}
            for row in rows:
                assert row.source_url == url and await evidence.verify(session, store, row.id)
            assert await session.scalar(select(func.count()).select_from(WatchedDomain)) == 0
        assert requests.count(TARGET) == 2  # Probe and screenshot both keep path + query.
        assert "/" not in requests
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        deps = ApiDeps(
            settings=Settings(cookie_secure=False),
            config=ConfigRuntime.static(sbr_rules),
            sessions=sessions,
            store=store,
            web_dist=DIST,
        )
        server = uvicorn.Server(
            uvicorn.Config(create_api(deps), host="127.0.0.1", port=port, log_level="warning")
        )
        task = asyncio.create_task(server.serve())
        async with asyncio.timeout(10):
            while not server.started:
                await asyncio.sleep(0.05)
        async with playwright_api.async_playwright() as pw:
            browser = await pw.chromium.launch()
            try:
                page = await browser.new_page()
                await page.goto(f"http://127.0.0.1:{port}/alerts/{alert_id}")
                await page.get_by_label("用户名").fill("url-analyst")
                await page.get_by_label("口令").fill(PASSWORD)
                await page.get_by_role("button", name="登录").click()
                expect = playwright_api.expect
                await expect(page.get_by_text("URL 品牌词", exact=True)).to_be_visible()
                await expect(page.get_by_text("情报命中", exact=True)).to_be_visible()
                await expect(page.get_by_role("link", name=url, exact=True)).to_have_count(0)
                image = page.get_by_role("img", name="截图")
                await expect(image).to_be_visible()
                await expect(image).to_have_js_property("naturalWidth", 1366)
                await page.screenshot(path=str(tmp_path / "url-triage.png"), full_page=True)
                await page.get_by_label("误报").check()
                await expect(page.get_by_text("以后不再告警", exact=True)).to_have_count(0)
                await page.get_by_label("说明").fill("受控 URL 验收，关闭合成告警")
                await page.get_by_role("button", name="提交").click()
                await expect(page.get_by_text("研判结论已提交")).to_be_visible()
            finally:
                await browser.close()
        async with sessions.begin() as session:
            replay = await processor.process(session, items[0])
            assert replay.alerts == [] and replay.findings == []
            assert await session.scalar(select(func.count()).select_from(Alert)) == 1
            assert await session.scalar(select(func.count()).select_from(SuppressionRule)) == 0
            assert await audit.verify_chain(session) is None
    finally:
        if server is not None:
            server.should_exit = True
        if task is not None:
            await task
        await probe_http.aclose()
        await sandbox_http.aclose()
        await engine.dispose()
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=5)
