"""Owned mail/intake/DMARC/syslog signals → Taskiq → PostgreSQL → analyst browser."""

import asyncio
import hashlib
import hmac
import json
import socket
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import uvicorn
from sqlalchemy import func, select

from opti.api import security
from opti.api.app import create_api
from opti.api.deps import ApiDeps
from opti.configs.runtime import ConfigRuntime
from opti.connectors.dmarc.connector import DmarcConnector
from opti.connectors.report_mailbox.connector import ReportMailboxConnector
from opti.core.config import ProjectRules
from opti.db import audit
from opti.db.models import Alert, Entity, Finding, RawItemRow, SuppressionRule, WatchedDomain
from opti.intake.app import IntakeDeps, create_intake
from opti.intake.forward import direct_forwarder
from opti.pipeline.app import build_app, set_app
from opti.pipeline.broker import broker
from opti.pipeline.retention import purge_report_contacts
from opti.pipeline.tasks import ingest
from opti.referer.logs import AccessRecord, RefererAggregator
from opti.sdk.models import raw_item_to_dict
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context
from opti.settings import Settings
from opti.storage.objects import MemoryObjectStore
from tests.connectors.test_dmarc import SECRETS as DMARC_SECRETS
from tests.connectors.test_dmarc import handler as dmarc_handler
from tests.connectors.test_report_mailbox import SECRETS as MAIL_SECRETS
from tests.connectors.test_report_mailbox import handler as mail_handler

pytestmark = [pytest.mark.db, pytest.mark.browser]
playwright_api = pytest.importorskip("playwright.async_api")
DIST = Path(__file__).resolve().parents[2] / "web" / "dist"
PASSWORD = "correct horse battery staple"


async def test_owned_data_to_triage(
    clean_db: str, sbr_rules: ProjectRules, sbr_rules_path: Path, tmp_path: Path
) -> None:
    assert (DIST / "index.html").exists(), "先构建前端"
    app = await build_app(
        Settings(
            database_url=clean_db,
            rules_path=sbr_rules_path,
            cookie_secure=False,
            alerting_config=tmp_path / "alerting.yaml",
        ),
        enrichers={},
        sinks=[],
        store=MemoryObjectStore(),
    )
    set_app(app)
    await broker.startup()
    server = None
    server_task = None
    try:
        started = time.monotonic()
        mailbox = ReportMailboxConnector(
            make_context(
                sbr_rules, connector_id="report_mailbox", handler=mail_handler, secrets=MAIL_SECRETS
            ),
            {"mailbox": "phishing@example.org"},
        )
        mail_items = [i async for i in mailbox.fetch(build_query_plan(sbr_rules))]
        assert len(mail_items) == 3  # .eml, Outlook itemAttachment and inline.
        for item in mail_items:
            task = await ingest.kiq(raw_item_to_dict(item))
            assert not (await task.wait_result()).is_err
        assert time.monotonic() - started < 600
        dmarc = DmarcConnector(
            make_context(
                sbr_rules, connector_id="dmarc", handler=dmarc_handler, secrets=DMARC_SECRETS
            ),
            {"mailbox": "dmarc@example.org", "authorized_networks": ["192.0.2.0/24"]},
        )
        async for item in dmarc.fetch(build_query_plan(sbr_rules)):
            task = await ingest.kiq(raw_item_to_dict(item))
            assert not (await task.wait_result()).is_err
        forward, _ = direct_forwarder()
        intake = create_intake(IntakeDeps(sbr_rules, forward, "t" * 32, b"k" * 32))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=intake), base_url="https://example.org"
        ) as client:
            assert (
                await client.get("/ti-intake/b/" + "t" * 32 + ".gif?h=clone-e2e.top")
            ).status_code == 200
            raw = json.dumps(
                {
                    "description": "自称 Sample Brand 贷款专员，要求先交手续费",
                    "urls": ["https://public-login.top/apply"],
                    "contact": "tel:private-test",
                }
            ).encode()
            ts = str(int(time.time()))
            signature = hmac.new(b"k" * 32, ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
            headers = {"X-Opti-Timestamp": ts, "X-Opti-Signature": signature}
            response = await client.post("/ti-intake/report", content=raw, headers=headers)
            assert response.status_code == 202
            report_id = response.json()["id"]
            assert (
                await client.post("/ti-intake/report", content=raw, headers=headers)
            ).status_code == 409
        aggregate = RefererAggregator(sbr_rules)
        for _ in range(3):
            aggregate.add(AccessRecord("hotlink-e2e.top", "/logo.png?visitor=secret", 200))
        for item in aggregate.flush(force=True):
            await forward(item)
        async with app.sessions.begin() as session:
            categories = set((await session.scalars(select(Finding.category))).all())
            assert categories == {"reported_phishing", "clone_site", "email_spoofing"}
            assert await session.scalar(select(func.count()).select_from(WatchedDomain)) == 2
            report = await session.scalar(
                select(Finding)
                .join(Entity)
                .where(Entity.type == "report", Entity.value == report_id)
            )
            assert report is not None and report.match["context"]["contact"] == "tel:private-test"
            alert_id = await session.scalar(
                select(Alert.id).where(Alert.routing["domain"].astext == report_id)
            )
            assert alert_id is not None
            raw_rows = (await session.scalars(select(RawItemRow))).all()
            assert "tel:private-test" not in str([row.payload for row in raw_rows])
            assert "employee@example.org" not in str([row.payload for row in raw_rows])
            assert "visitor=secret" not in str([row.payload for row in raw_rows])
            await security.create_user(
                session,
                username="owned-analyst",
                password=PASSWORD,
                roles=["analyst"],
                now=datetime.now(UTC),
            )
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        api = create_api(
            ApiDeps(
                settings=Settings(cookie_secure=False),
                config=ConfigRuntime.static(sbr_rules),
                sessions=app.sessions,
                store=None,
                web_dist=DIST,
            )
        )
        server = uvicorn.Server(
            uvicorn.Config(api, host="127.0.0.1", port=port, log_level="warning")
        )
        server_task = asyncio.create_task(server.serve())
        async with asyncio.timeout(10):
            while not server.started:
                await asyncio.sleep(0.05)
        async with playwright_api.async_playwright() as pw:
            browser = await pw.chromium.launch()
            try:
                page = await browser.new_page()
                await page.goto(f"http://127.0.0.1:{port}/alerts/{alert_id}")
                await page.get_by_label("用户名").fill("owned-analyst")
                await page.get_by_label("口令").fill(PASSWORD)
                await page.get_by_role("button", name="登录").click()
                expect = playwright_api.expect
                await expect(page.get_by_text("来源上下文", exact=True)).to_be_visible()
                await expect(
                    page.get_by_text(
                        "自称 Sample Brand 贷款专员，要求先交手续费", exact=True
                    )
                ).to_be_visible()
                await expect(page.get_by_text("机构自有信号", exact=True)).to_be_visible()
                await page.screenshot(
                    path=str(tmp_path / "owned-report-triage.png"), full_page=True
                )
                await page.get_by_label("误报").check()
                await expect(page.get_by_text("以后不再告警", exact=True)).to_have_count(0)
                await page.get_by_role("button", name="提交").click()
                await expect(page.get_by_text("研判结论已提交")).to_be_visible()
            finally:
                await browser.close()
        async with app.sessions.begin() as session:
            assert await purge_report_contacts(session, datetime.now(UTC) + timedelta(days=1)) == 1
            session.expire_all()
            report = await session.get(Finding, report.id)
            assert report is not None and report.match["context"]["contact"] is None
            assert await session.scalar(select(func.count()).select_from(SuppressionRule)) == 0
            assert await audit.verify_chain(session) is None
    finally:
        if server is not None:
            server.should_exit = True
        if server_task is not None:
            await server_task
        await broker.shutdown()
        set_app(None)
        await app.close()
