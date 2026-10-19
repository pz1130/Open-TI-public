"""A real admin switch updates a second user's page and restores historical data."""

import asyncio
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
import uvicorn
from sqlalchemy.ext.asyncio import create_async_engine

from opti.api import security
from opti.api.app import create_api
from opti.api.deps import ApiDeps
from opti.configs import projects
from opti.configs.runtime import ConfigRuntime
from opti.core.config import ProjectRules
from opti.db.engine import make_sessionmaker
from opti.pipeline.watchlist import ensure_watched
from opti.settings import Settings
from opti.storage.objects import MemoryObjectStore

pytestmark = [pytest.mark.browser, pytest.mark.db]
playwright_api = pytest.importorskip("playwright.async_api")
DIST = Path(__file__).resolve().parents[2] / "web" / "dist"
PASSWORD = "correct horse battery staple"


async def test_global_switch_in_two_browser_sessions(
    clean_db: str, sbr_rules: ProjectRules, sbr_rules_path: Path
) -> None:
    if not (DIST / "index.html").exists():
        pytest.skip("先构建前端：pnpm -C web build")
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    now = datetime.now(UTC)
    async with sessions.begin() as s:
        for username, roles in (("admin", ["platform_admin"]), ("viewer", ["viewer"])):
            await security.create_user(
                s, username=username, password=PASSWORD, roles=roles, now=now
            )
        await projects.save(s, sbr_rules)
        await projects.save(s, sbr_rules.model_copy(update={"project": "second"}))
        await ensure_watched(s, sbr_rules.project, "sbr-loans.com", reason="test", now=now)
    deps = ApiDeps(
        settings=Settings(database_url=clean_db, rules_path=sbr_rules_path, cookie_secure=False),
        config=ConfigRuntime.static(sbr_rules, sessions=sessions),
        sessions=sessions,
        store=MemoryObjectStore(),
        web_dist=DIST,
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(create_api(deps), host="127.0.0.1", port=port, log_level="warning")
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    try:
        async with playwright_api.async_playwright() as pw:
            browser = await pw.chromium.launch()
            admin_context = await browser.new_context(viewport={"width": 1440, "height": 1000})
            viewer_context = await browser.new_context()
            admin, viewer = await admin_context.new_page(), await viewer_context.new_page()
            expect = playwright_api.expect

            async def sign_in(page, username, path):
                await page.goto(base + path)
                await page.get_by_label("用户名").fill(username)
                await page.get_by_label("口令").fill(PASSWORD)
                await page.get_by_role("button", name="登录", exact=True).click()
                await expect(page.locator(".oti-operator")).to_contain_text(username)

            await sign_in(admin, "admin", "/settings/projects")
            await sign_in(viewer, "viewer", "/watchlist?tab=domains")
            await expect(viewer.get_by_text("sbr-loans.com", exact=True)).to_be_visible()
            await expect(
                viewer.get_by_role("button", name=f"当前项目：{sbr_rules.project}", exact=True)
            ).to_have_count(0)

            async def switch(project):
                row = (
                    admin.get_by_role("row").filter(has=admin.get_by_text(project, exact=True)).last
                )
                await row.get_by_role("button", name="切换项目", exact=True).click()
                modal = admin.get_by_role("dialog")
                await expect(modal.get_by_text("此操作切换整个平台", exact=False)).to_be_visible()
                await modal.get_by_role("button", name="切换项目", exact=True).click()
                await expect(
                    admin.get_by_role("button", name=f"当前项目：{project}", exact=True)
                ).to_be_visible(timeout=15000)
                await expect(modal).to_have_count(0)

            await switch("second")
            await expect(viewer.get_by_text("当前项目：second", exact=True)).to_be_visible(
                timeout=15000
            )
            await viewer.goto(base + "/watchlist?tab=domains")
            await expect(viewer.get_by_text("sbr-loans.com", exact=True)).to_have_count(0)
            await switch(sbr_rules.project)
            await expect(
                viewer.get_by_text(f"当前项目：{sbr_rules.project}", exact=True)
            ).to_be_visible(timeout=15000)
            await viewer.goto(base + "/watchlist?tab=domains")
            await expect(viewer.get_by_text("sbr-loans.com", exact=True)).to_be_visible()
            await admin.set_viewport_size({"width": 390, "height": 844})
            assert await admin.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            await browser.close()
    finally:
        server.should_exit = True
        await task
        await engine.dispose()
