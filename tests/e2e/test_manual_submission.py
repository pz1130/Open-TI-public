"""Browser flow for submitting platform and ordinary web leads with screenshot evidence."""

import asyncio
import io
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
import uvicorn
from PIL import Image
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.api import security
from opti.api.app import create_api
from opti.api.deps import ApiDeps
from opti.configs.runtime import ConfigRuntime
from opti.configs.testing import override
from opti.core.config import ProjectRules
from opti.db.engine import make_sessionmaker
from opti.db.models import Alert, Evidence, WatchedDomain
from opti.settings import Settings
from opti.storage.objects import MemoryObjectStore
from opti.takedown.config import load_takedown_config

REPO = Path(__file__).resolve().parents[2]
DIST = REPO / "web" / "dist"
PASSWORD = "correct horse battery staple"
playwright_api = pytest.importorskip("playwright.async_api")
pytestmark = pytest.mark.db


async def test_submit_platform_and_web_leads(
    clean_db: str, sbr_rules: ProjectRules, tmp_path: Path
) -> None:
    if not (DIST / "index.html").exists():
        pytest.skip("build the frontend first: pnpm -C web run build")
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    async with sessions.begin() as s:
        await security.create_user(
            s, username="alice", password=PASSWORD, roles=["analyst"], now=datetime.now(UTC)
        )
    deps = ApiDeps(
        settings=Settings(cookie_secure=False),
        config=ConfigRuntime.static(sbr_rules),
        sessions=sessions,
        store=MemoryObjectStore(),
        web_dist=DIST,
    )
    override(
        deps.config, takedown=load_takedown_config(REPO / "config" / "takedown" / "platforms.yaml")
    )
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(create_api(deps), host="127.0.0.1", port=port, log_level="warning")
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    shot = tmp_path / "shot.png"
    buf = io.BytesIO()
    Image.new("RGB", (60, 40), "blue").save(buf, format="PNG")
    shot.write_bytes(buf.getvalue())
    try:
        async with playwright_api.async_playwright() as pw:
            browser = await pw.chromium.launch()
            page = await browser.new_page()
            expect = playwright_api.expect
            await page.goto(f"{base}/alerts")
            await page.get_by_label("用户名").fill("alice")
            await page.get_by_label("口令").fill(PASSWORD)
            await page.get_by_role("button", name="登录").click()
            await page.get_by_role("button", name="提交线索").click()
            await page.get_by_label("链接").fill("https://www.linkedin.com/in/fake-sbr-ceo/")
            await expect(
                page.get_by_text("LinkedIn 链接：平台不会访问该页面", exact=False)
            ).to_be_visible()
            await page.get_by_label("说明").fill("冒充行长发布招聘")
            await page.locator("input[type=file]").set_input_files(str(shot))
            await page.get_by_role("button", name="提交", exact=True).click()
            await page.wait_for_url(f"{base}/alerts/*")
            await expect(page.get_by_text("alice 上传", exact=False)).to_be_visible()
            await page.goto(f"{base}/alerts")
            await page.get_by_role("button", name="提交线索").click()
            await page.get_by_label("链接").fill("https://sbr-careers.top/apply")
            await expect(
                page.get_by_text("平台会用隔离浏览器自动截图", exact=False)
            ).to_be_visible()
            await page.get_by_label("冒名诈骗").check()
            await page.get_by_label("说明").fill("虚假招聘收费")
            await page.get_by_role("button", name="提交", exact=True).click()
            await page.wait_for_url(f"{base}/alerts/*")
            await browser.close()
    finally:
        server.should_exit = True
        await task
    async with sessions() as s:
        alerts = (await s.scalars(select(Alert).order_by(Alert.id))).all()
        assert [a.evidence_status for a in alerts] == ["none", "pending"]
        uploads = (await s.scalars(select(Evidence).where(Evidence.kind == "upload"))).all()
        assert len(uploads) == 1 and uploads[0].alert_id == alerts[0].id
        assert (await s.scalars(select(WatchedDomain.domain))).all() == ["sbr-careers.top"]
    await engine.dispose()
