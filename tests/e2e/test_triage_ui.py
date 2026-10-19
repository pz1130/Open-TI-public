import asyncio
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
import uvicorn
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from opti.api import security
from opti.api.app import create_api
from opti.api.deps import ApiDeps
from opti.configs.runtime import ConfigRuntime
from opti.core.config import ProjectRules
from opti.core.scoring import Category, Score, Severity
from opti.db import audit, repo
from opti.db.engine import make_sessionmaker
from opti.db.models import Evidence, SuppressionRule
from opti.settings import Settings
from opti.storage.artifacts import store_saver
from opti.storage.objects import MemoryObjectStore

pytestmark = [pytest.mark.browser, pytest.mark.db]
playwright_api = pytest.importorskip("playwright.async_api")
DIST = Path(__file__).resolve().parents[2] / "web" / "dist"
PASSWORD = "correct horse battery staple"
PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082"
)


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def test_triage_flow_in_real_browser(clean_db: str, sbr_rules: ProjectRules) -> None:
    if not (DIST / "index.html").exists():
        pytest.skip("先构建前端：pnpm -C web run build")
    now = datetime.now(UTC)
    engine = create_async_engine(clean_db)
    sessions = make_sessionmaker(engine)
    store = MemoryObjectStore()
    async with sessions.begin() as s:
        await security.create_user(
            s, username="alice", password=PASSWORD, roles=["analyst"], now=now
        )
        for username, role in (("vic", "viewer"), ("audrey", "auditor")):
            await security.create_user(
                s, username=username, password=PASSWORD, roles=[role], now=now
            )
        await repo.upsert_project(s, sbr_rules)
        e = await repo.upsert_entity(s, "domain", "sbr-loans.com", now)
        up = await repo.upsert_finding(
            s, project_id=sbr_rules.project, entity=e,
            score=Score(72, Severity.HIGH, Category.TYPOSQUAT_DOMAIN, {"base": 20, "domain_risk": 40, "content_risk": 12}),
            match={"reasons": [{"reason": "brand_label", "token": "sbr", "label": "sbr-loans", "where": "registered"}]},
            source="certstream", now=now,
        )  # fmt: skip
        alert = await repo.open_alert(s, up.finding, Severity.HIGH, now)
        ref = await store_saver(store, node_id="hk1")(PNG_1PX, "image/png")
        s.add(Evidence(
            finding_id=up.finding.id, alert_id=alert.id, kind="screenshot", object_key=ref["key"],
            sha256=ref["sha256"], size=ref["size"], content_type="image/png", version_id=ref["version_id"],
            captured_at=now, node_id="hk1", method="opti-sandbox/test", source_url="https://sbr-loans.com/",
        ))  # fmt: skip
        alert_id = alert.id
    deps = ApiDeps(
        settings=Settings(cookie_secure=False),
        config=ConfigRuntime.static(sbr_rules),
        sessions=sessions,
        store=store,
        web_dist=DIST,
    )
    port = _port()
    server = uvicorn.Server(
        uvicorn.Config(create_api(deps), host="127.0.0.1", port=port, log_level="warning")
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    csp_errors: list[str] = []
    try:
        async with playwright_api.async_playwright() as pw:
            browser = await pw.chromium.launch()
            page = await browser.new_page()
            page.on(
                "console",
                lambda m: (
                    csp_errors.append(m.text) if "Content Security Policy" in m.text else None
                ),
            )
            expect = playwright_api.expect
            account = page.locator(".oti-operator")  # 顶栏账号菜单（标题随语言变化）

            async def log_out() -> None:
                await account.click()
                await page.get_by_role("menuitem", name="Log out").click()

            await page.goto(f"{base}/alerts/{alert_id}")  # Teams 告警中的链接格式
            await page.get_by_label("用户名").fill("alice")
            await page.get_by_label("口令").fill(PASSWORD)
            await page.get_by_role("button", name="登录").click()
            await expect(page.get_by_text("域名风险")).to_be_visible()
            img = page.get_by_role("img", name="截图")
            await expect(img).to_be_visible()
            assert await img.evaluate("el => el.naturalWidth") == 1
            await page.get_by_label("误报").check()
            await page.get_by_label("整个可注册域（含子域）").check()
            await page.get_by_label("说明").fill("e2e")
            await page.get_by_role("button", name="提交").click()
            await expect(page.get_by_text("研判结论已提交")).to_be_visible()
            await page.get_by_text("English").click()
            await account.click()
            await expect(page.get_by_role("menuitem", name="Log out")).to_be_visible()
            await page.keyboard.press("Escape")
            await page.goto(f"{base}/alerts")
            await expect(page.get_by_text("Alert queue")).to_be_visible()
            await expect(page.get_by_text("sbr-loans.com")).to_have_count(
                0
            )  # 已关闭，不在默认队列中
            # Cookie 存在也不能绕过 CSRF 检查。
            assert (await page.request.post(f"{base}/api/v1/auth/logout")).status == 403
            await page.reload()
            await expect(account).to_contain_text("alice")
            await log_out()
            await page.get_by_label("Username").fill("vic")
            await page.get_by_label("Password").fill(PASSWORD)
            await page.get_by_role("button", name="Sign in", exact=True).click()
            await expect(account).to_contain_text("vic")
            await page.goto(f"{base}/alerts/{alert_id}")
            await expect(page.get_by_text("Domain risk", exact=True)).to_be_visible()
            await expect(page.get_by_role("button", name="Submit", exact=True)).to_have_count(0)
            await expect(page.get_by_role("img", name="Screenshot", exact=True)).to_have_count(0)
            await expect(page.get_by_role("link", name="sbr-loans.com", exact=True)).to_have_count(
                0
            )
            await log_out()
            await page.get_by_label("Username").fill("audrey")
            await page.get_by_label("Password").fill(PASSWORD)
            await page.get_by_role("button", name="Sign in", exact=True).click()
            await expect(account).to_contain_text("audrey")
            await page.goto(base)
            # 审计员只读：审计日志、大模型研判、设置三个导航入口，没有告警与下架
            await expect(page.locator(".oti-nav .oti-nav-item")).to_have_text(
                ["LLM adjudication", "Audit log", "Settings"]
            )
            await page.get_by_role("button", name="Verify integrity").click()
            await expect(page.get_by_role("alert")).to_contain_text("intact")
            await browser.close()
    finally:
        server.should_exit = True
        await task
    assert csp_errors == []
    async with sessions() as s:
        rule = (await s.scalars(select(SuppressionRule))).one()
        assert await audit.verify_chain(s) is None
        assert rule.value == "sbr-loans.com" and rule.kind == "registered_domain"
    await engine.dispose()
