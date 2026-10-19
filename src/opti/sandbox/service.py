"""截图沙箱服务（设计文档 5.4、10.2）：在隔离容器里用无头 Chromium 打开可疑页面，返回截图、HTML 快照与重定向链。

每次截图启动一个全新的浏览器（无 Cookie、无缓存），禁用下载与 Service Worker，只放行 GET/HEAD 与公网地址。
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from opti.enrichers.http_probe.enricher import resolve_addresses
from opti.sandbox.favicon import favicon_fingerprint, icon_url, same_origin
from opti.sandbox.guard import Resolver, request_allowed
from opti.sandbox.ocr import recognize
from opti.sandbox.proxy import pinned_proxy
from opti.sandbox.visual import IMAGE_BOX_SCRIPT, image_candidates
from opti.sdk.http import DEFAULT_USER_AGENT

MAX_HTML_BYTES = 2 * 1024 * 1024
CAPTURE_GRACE = 15.0  # 页面超时之外，留给截图与读取 HTML 的时间
CaptureFn = Callable[[str, float], Awaitable[dict[str, Any]]]


class CaptureRequest(BaseModel):
    url: str = Field(pattern=r"^https?://", max_length=2048)
    timeout: float = Field(default=20.0, gt=0, le=60)


def create_sandbox(capture: CaptureFn, *, concurrency: int = 2) -> FastAPI:
    app = FastAPI(title="Open-TI 截图沙箱", docs_url=None, redoc_url=None, openapi_url=None)
    slots = asyncio.Semaphore(concurrency)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/capture")
    async def capture_page(req: CaptureRequest) -> dict[str, Any]:
        async with slots:
            try:
                return await asyncio.wait_for(
                    capture(req.url, req.timeout), req.timeout + CAPTURE_GRACE
                )
            except TimeoutError:
                return {"url": req.url, "error": "TimeoutError"}

    return app


class PlaywrightCapture:
    def __init__(
        self,
        *,
        allow_private: bool = False,
        resolve: Resolver = resolve_addresses,
        ocr_enabled: bool = False,
    ) -> None:
        self._allow_private = allow_private  # 仅供测试；生产必须为 False
        self._resolve = resolve
        self._ocr_enabled = ocr_enabled

    async def __call__(self, url: str, timeout: float) -> dict[str, Any]:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright

        blocked: list[str] = []
        favicon_allowed_url: str | None = None

        async with (
            pinned_proxy(
                resolve=self._resolve, allow_private=self._allow_private, blocked=blocked
            ) as proxy,
            async_playwright() as pw,
        ):
            browser = await pw.chromium.launch(
                proxy={"server": proxy.url},
                args=["--proxy-bypass-list=<-loopback>", "--disable-quic"],
            )
            try:
                context = await browser.new_context(
                    accept_downloads=False,
                    ignore_https_errors=True,  # 钓鱼站常用无效证书；只取证，不信任
                    service_workers="block",
                    user_agent=DEFAULT_USER_AGENT,
                    viewport={"width": 1366, "height": 768},
                )
                await context.route_web_socket("**/*", lambda ws: ws.close())
                page = await context.new_page()
                documents: list[Any] = []

                def document_response(response: Any) -> None:
                    if (
                        response.request.resource_type == "document"
                        and response.request.frame == page.main_frame
                    ):
                        documents.append(response)

                page.on("response", document_response)
                # CDP Fetch pauses every redirect hop. Playwright route.continue_()
                # only handles the first request of a redirect chain.
                cdp = await context.new_cdp_session(page)

                async def guard(event: dict[str, Any]) -> None:
                    request = event["request"]
                    allowed = (
                        favicon_allowed_url is None
                        or (request["method"] == "GET" and request["url"] == favicon_allowed_url)
                    ) and await request_allowed(
                        request["method"],
                        request["url"],
                        resolve=self._resolve,
                        allow_private=self._allow_private,
                    )
                    if allowed:
                        await cdp.send("Fetch.continueRequest", {"requestId": event["requestId"]})
                    else:
                        blocked.append(request["url"][:300])
                        await cdp.send(
                            "Fetch.failRequest",
                            {
                                "requestId": event["requestId"],
                                "errorReason": "BlockedByClient",
                            },
                        )

                cdp.on("Fetch.requestPaused", guard)
                await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*"}]})
                # Screenshots never require auxiliary windows.
                context.on("page", lambda popup: popup.close())
                try:
                    resp = await page.goto(
                        url, wait_until="domcontentloaded", timeout=timeout * 1000
                    )
                    await page.wait_for_timeout(1000)  # 让脚本渲染出的登录框出现
                except PlaywrightError as e:
                    first = str(e).splitlines()[0][:200] if str(e) else type(e).__name__
                    return {"url": url, "error": f"navigation: {first}", "blocked": blocked[:20]}
                png = await page.screenshot(type="png", scale="css")
                try:
                    boxes = await page.evaluate(IMAGE_BOX_SCRIPT)
                    candidates = image_candidates(png, boxes if isinstance(boxes, list) else [])
                except (PlaywrightError, OSError, ValueError):
                    candidates = []  # 可选视觉分析失败不能阻断截图存证
                html = (await page.content()).encode("utf-8")[:MAX_HTML_BYTES]
                try:
                    page_text = (await page.locator("body").inner_text(timeout=2000))[:200_000]
                except PlaywrightError:
                    page_text = ""
                resp = documents[-1] if documents else resp
                final_url = page.url
                title = (await page.title())[:300]
                ocr_text = await recognize(png) if self._ocr_enabled else None
                redirects: list[str] = []
                req = resp.request if resp is not None else None
                while req is not None and req.redirected_from is not None:
                    req = req.redirected_from
                    redirects.append(req.url)
                redirects.reverse()
                if final_url != url and (not redirects or redirects[0] != url):
                    redirects.insert(0, url)
                favicon: dict[str, Any] | None = None
                try:
                    href = await page.evaluate(
                        "() => document.querySelector('link[rel~=icon]')?.getAttribute('href') ?? null"
                    )
                    selected = icon_url(final_url, href if isinstance(href, str) else None)
                    if selected is not None:
                        favicon_allowed_url = selected
                        icon_response = await page.goto(selected, wait_until="commit", timeout=5000)
                        if (
                            icon_response is not None
                            and icon_response.status == 200
                            and same_origin(final_url, icon_response.url)
                        ):
                            body = await asyncio.wait_for(icon_response.body(), 5)
                            fingerprint = favicon_fingerprint(body)
                            if fingerprint is not None:
                                favicon = {"url": icon_response.url, **fingerprint}
                except (PlaywrightError, OSError, ValueError, TimeoutError):
                    pass  # 可选指纹失败不影响先前已拍下的证据
                return {
                    "url": url,
                    "final_url": final_url,
                    "status": resp.status if resp is not None else None,
                    "title": title,
                    "page_text": page_text,
                    "content_type": resp.headers.get("content-type", "")
                    if resp is not None
                    else "",
                    "redirects": redirects,
                    "blocked": blocked[:20],
                    "browser": f"chromium {browser.version}",
                    "captured_at": datetime.now(UTC).isoformat(),
                    "screenshot_b64": base64.b64encode(png).decode(),
                    "html_b64": base64.b64encode(html).decode(),
                    "visual_candidates": candidates,
                    "favicon": favicon,
                    **({"ocr_text": ocr_text} if ocr_text is not None else {}),
                }
            finally:
                await browser.close()
