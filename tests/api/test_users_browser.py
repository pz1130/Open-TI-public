import asyncio
import re
import socket
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from opti.api.app import create_api
from tests.api.conftest import PASSWORD

pytestmark = [pytest.mark.db, pytest.mark.browser]
playwright_api = pytest.importorskip("playwright.async_api")
DIST = Path(__file__).resolve().parents[2] / "web" / "dist"


async def test_manage_role_set_and_local_user_in_browser(
    api: Any, make_user: Any, tmp_path: Path
) -> None:
    if not (DIST / "index.html").exists():
        pytest.skip("先构建前端：pnpm -C web build")
    await make_user("root", ("superadmin",))
    api.deps.web_dist = DIST
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
            page = await browser.new_page(viewport={"width": 1440, "height": 1050})
            page.set_default_timeout(10000)
            expect = playwright_api.expect
            await page.goto(base + "/settings/access")
            await page.get_by_label("用户名", exact=True).fill("root")
            await page.get_by_label("口令", exact=True).fill(PASSWORD)
            await page.get_by_role("button", name="登录", exact=True).click()
            await page.get_by_role("tab", name="权限集", exact=True).click()
            await page.get_by_role("button", name="新建权限集", exact=True).click()
            dialog = page.get_by_role("dialog")
            await dialog.get_by_label("标识", exact=True).fill("web_monitor")
            await dialog.get_by_label("名称", exact=True).fill("测试监测集")
            checkbox = dialog.get_by_role("checkbox", name=re.compile("查看监视列表和关键词"))
            await dialog.get_by_text("查看监视列表和关键词", exact=True).click()
            await expect(checkbox).to_be_checked()
            await dialog.get_by_role("button", name="保存", exact=True).click()
            await expect(dialog).to_be_hidden()
            await page.get_by_role("tab", name="角色", exact=True).click()
            await page.get_by_role("button", name="新建角色", exact=True).click()
            dialog = page.get_by_role("dialog")
            await dialog.get_by_label("标识", exact=True).fill("web_team")
            await dialog.get_by_label("名称", exact=True).fill("测试团队")
            await dialog.get_by_role("combobox", name="权限集", exact=True).click()
            await dialog.get_by_role("combobox", name="权限集", exact=True).fill("测试监测集")
            await (
                page.locator(".ant-select-dropdown:visible .ant-select-item-option")
                .filter(has_text="测试监测集")
                .click()
            )
            await page.keyboard.press("Escape")
            await dialog.get_by_role("button", name="保存", exact=True).click()
            await expect(dialog).to_be_hidden()
            await page.screenshot(path=str(tmp_path / "access-roles.png"), animations="disabled")
            await page.goto(base + "/settings/users")
            await page.get_by_role("button", name="创建本地用户", exact=True).click()
            dialog = page.get_by_role("dialog")
            await dialog.get_by_label("用户名", exact=True).fill("webuser")
            await dialog.get_by_label("显示名称", exact=True).fill("监测操作员")
            await dialog.get_by_label("初始密码", exact=True).fill(PASSWORD)
            await dialog.get_by_role("combobox", name="角色", exact=True).click()
            await dialog.get_by_role("combobox", name="角色", exact=True).fill("测试团队")
            await (
                page.locator(".ant-select-dropdown:visible .ant-select-item-option")
                .filter(has_text="测试团队")
                .click()
            )
            await page.keyboard.press("Escape")
            await expect(dialog.get_by_text("实际权限预览（1 项）", exact=True)).to_be_visible()
            await dialog.get_by_role("button", name="保存", exact=True).click()
            await expect(dialog).to_be_hidden()
            await expect(page.get_by_text("webuser", exact=True)).to_be_visible()
            await page.screenshot(path=str(tmp_path / "users-desktop.png"), animations="disabled")
            await page.set_viewport_size({"width": 390, "height": 844})
            await expect(page.get_by_role("heading", name="用户管理", exact=True)).to_be_visible()
            await page.screenshot(path=str(tmp_path / "users-mobile.png"), animations="disabled")
            await page.set_viewport_size({"width": 1440, "height": 1050})
            other_context = await browser.new_context()
            other = await other_context.new_page()
            await other.goto(base)
            await other.get_by_label("用户名", exact=True).fill("webuser")
            await other.get_by_label("口令", exact=True).fill(PASSWORD)
            await other.get_by_role("button", name="登录", exact=True).click()
            await expect(other.get_by_role("heading", name="修改密码", exact=True)).to_be_visible()
            await other.get_by_label("当前密码", exact=True).fill(PASSWORD)
            new_password = "a newly changed secret password"
            await other.get_by_label("新密码", exact=True).fill(new_password)
            await other.get_by_label("确认新密码", exact=True).fill(new_password)
            await other.get_by_role("button", name="修改密码", exact=True).click()
            await other.get_by_label("用户名", exact=True).fill("webuser")
            await other.get_by_label("口令", exact=True).fill(new_password)
            await other.get_by_role("button", name="登录", exact=True).click()
            await expect(other.get_by_role("tab", name="监视域名", exact=True)).to_be_visible()
            assert (await other.request.get(base + "/api/v1/admin/users")).status == 403
            # User password changes increment the account version. Refresh before editing.
            await page.reload()
            row = page.get_by_role("row").filter(has_text="webuser")
            await row.get_by_role("button", name="编辑", exact=True).click()
            dialog = page.get_by_role("dialog")
            await dialog.get_by_role("switch").uncheck()
            await dialog.get_by_role("button", name="保存", exact=True).click()
            await expect(dialog).to_be_hidden()
            assert (await other.request.get(base + "/api/v1/auth/me")).status == 401
            await expect(row.get_by_text("已停用", exact=True)).to_be_visible()
            await row.get_by_role("button", name="更多", exact=True).click()
            await page.get_by_role("menuitem", name="启用账号", exact=True).click()
            confirmation = page.get_by_role("dialog")
            await confirmation.get_by_role("button", name="确定", exact=True).click()
            await expect(confirmation).to_be_hidden()
            await expect(row.get_by_text("启用", exact=True)).to_be_visible()
            await row.get_by_role("button", name="更多", exact=True).click()
            await page.get_by_role("menuitem", name="重设密码", exact=True).click()
            dialog = page.get_by_role("dialog")
            reset_password = "a newly reset secret password"
            await dialog.get_by_label("新密码", exact=True).fill(reset_password)
            await dialog.get_by_label("确认新密码", exact=True).fill(reset_password)
            await dialog.get_by_role("button", name="保存", exact=True).click()
            await expect(dialog).to_be_hidden()
            await other.goto(base)
            await other.get_by_label("用户名", exact=True).fill("webuser")
            await other.get_by_label("口令", exact=True).fill(reset_password)
            await other.get_by_role("button", name="登录", exact=True).click()
            await expect(other.get_by_role("heading", name="修改密码", exact=True)).to_be_visible()
            await browser.close()
    finally:
        server.should_exit = True
        await task
