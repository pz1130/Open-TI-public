import asyncio
import socket
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from tests.api.conftest import PASSWORD
from tests.api.test_keyword_scan import prepare

pytestmark = [pytest.mark.db, pytest.mark.browser]
playwright_api = pytest.importorskip("playwright.async_api")
DIST = Path(__file__).resolve().parents[2] / "web" / "dist"


async def test_manual_scan_on_both_pages(
    api: Any, make_user: Any, monkeypatch: Any, tmp_path: Path
) -> None:
    if not (DIST / "index.html").exists():
        pytest.skip("先构建前端：pnpm -C web build")
    await make_user()
    queued = prepare(api, monkeypatch)
    api.deps.web_dist = DIST
    # create_api's static mount is configured at construction.
    from opti.api.app import create_api

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(create_api(api.deps), host="127.0.0.1", port=port, log_level="warning")
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    try:
        async with playwright_api.async_playwright() as pw:
            browser = await pw.chromium.launch()
            page = await browser.new_page(viewport={"width": 1440, "height": 1000})
            page.set_default_timeout(10000)
            expect = playwright_api.expect
            await page.goto(base + "/watchlist")
            await page.get_by_label("用户名").fill("alice")
            await page.get_by_label("口令").fill(PASSWORD)
            await page.get_by_role("button", name="登录", exact=True).click()
            panel = page.get_by_test_id("keyword-scan-panel")
            await panel.get_by_role("combobox", name="本次扫描词").focus()
            await panel.get_by_role("combobox", name="本次扫描词").press("ArrowDown")
            await (
                page.locator(".ant-select-dropdown:visible .ant-select-item-option")
                .filter(has_text="samplebrand")
                .click()
            )
            await panel.get_by_role("button", name="立即扫描", exact=True).click()
            await expect(panel.get_by_text("已排队", exact=True)).to_have_count(3)
            assert {spec["term"] for _, spec in queued} == {"samplebrand"}
            await page.goto(base + "/settings/rules")
            panel = page.get_by_test_id("keyword-scan-panel")
            await panel.get_by_role("combobox", name="本次扫描词").focus()
            await panel.get_by_role("combobox", name="本次扫描词").press("ArrowDown")
            await (
                page.locator(".ant-select-dropdown:visible .ant-select-item-option")
                .filter(has_text="Sample Brand")
                .click()
            )
            await panel.get_by_role("button", name="立即扫描", exact=True).click()
            await expect(panel.get_by_text("已排队", exact=True)).to_have_count(7)
            assert {spec["scope"] for _, spec in queued} == {"text", "domain"}
            await page.keyboard.press("Escape")
            await expect(page.locator(".ant-select-dropdown:visible")).to_have_count(0)
            await page.screenshot(path=str(tmp_path / "keyword-scan.png"), animations="disabled")
            await page.set_viewport_size({"width": 390, "height": 844})
            await expect(panel).to_be_visible()
            assert await panel.evaluate("el => el.scrollWidth <= el.clientWidth")
            await page.screenshot(
                path=str(tmp_path / "keyword-scan-mobile.png"), animations="disabled"
            )
            await browser.close()
    finally:
        server.should_exit = True
        await task
