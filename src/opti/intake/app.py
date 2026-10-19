"""对外入口（设计文档 4.12）：克隆站金丝雀回调与公众举报。

这是平台唯一面向公众的程序：不持有数据库凭据，只把数据转交给平台（经采集网关或任务队列）。
可挂在使用机构网站的反向代理后（如 https://www.example.org/ti-intake/），也可单独部署在对外主机。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from opti.configs.edge import EdgeRules
from opti.core.config import ProjectRules
from opti.core.domains import parse_domain
from opti.core.text_match import TextMatcher
from opti.core.urls import normalize_url
from opti.sdk.models import RawItem, utcnow

GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
MAX_BODY = 64 * 1024
MAX_SKEW = 300
_TRACKED_MAX = 10_000
log = logging.getLogger("opti.intake")


@dataclass
class IntakeDeps:
    rules: ProjectRules
    forward: Callable[[RawItem], Awaitable[None]]
    canary_token: str
    report_key: bytes
    prefix: str = "/ti-intake"
    clock: Callable[[], float] = field(default=time.time)
    canary_interval: float = 600.0
    edge: EdgeRules | None = None


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    description: str = Field(min_length=1, max_length=4000)
    urls: list[str] = Field(default_factory=list, max_length=20)
    contact: str | None = Field(default=None, max_length=200)
    category: Literal["loan", "job", "investment", "other"] = "other"
    observed_at: str | None = Field(default=None, max_length=40)
    lang: str | None = Field(default=None, max_length=10)


def _prune(seen: dict[str, float], now: float, ttl: float) -> None:
    for key in [k for k, t in seen.items() if now - t > ttl]:
        del seen[key]


def create_intake(deps: IntakeDeps) -> FastAPI:
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", deps.canary_token) or len(deps.report_key) < 32:
        raise ValueError(
            "需要 OPTI_SECRET_INTAKE_CANARY_TOKEN（16–128 位字母数字）与 OPTI_SECRET_INTAKE_REPORT_KEY（≥32 字符）"
        )
    app = FastAPI(title="Open-TI intake", docs_url=None, redoc_url=None, openapi_url=None)
    prefix = "/" + deps.prefix.strip("/")
    cache: dict[int, tuple[ProjectRules, set[str], TextMatcher]] = {}

    def view() -> tuple[ProjectRules, set[str], TextMatcher]:
        rules = deps.edge.current if deps.edge is not None else deps.rules
        hit = cache.get(id(rules))
        if hit is None or hit[0] is not rules:
            hit = (rules, {d.lower() for d in rules.domains.official}, TextMatcher(rules))
            cache.clear()
            cache[id(rules)] = hit
        return hit

    beacons: dict[str, float] = {}
    signatures: dict[str, float] = {}

    def gif() -> Response:
        return Response(GIF, media_type="image/gif", headers={"Cache-Control": "no-store"})

    @app.get(prefix + "/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get(prefix + "/b/{token}.gif")
    async def beacon(token: str, request: Request, v: str = "js", h: str | None = None) -> Response:
        rules, official, _ = view()
        if not hmac.compare_digest(token.encode(), deps.canary_token.encode()):
            return gif()  # 与成功时相同的响应：不泄露令牌是否正确
        variant = "css" if v == "css" else "js"
        try:
            raw = h if variant == "js" else urlsplit(request.headers.get("referer", "")).hostname
        except ValueError:
            return gif()
        if not raw or len(raw) > 253:
            return gif()
        parts = parse_domain(raw)
        if parts is None or any(parts.fqdn == d or parts.fqdn.endswith("." + d) for d in official):
            return gif()
        now = deps.clock()
        _prune(beacons, now, deps.canary_interval)
        if parts.fqdn in beacons or len(beacons) >= _TRACKED_MAX:
            return gif()
        beacons[parts.fqdn] = now
        bucket = time.strftime("%Y%m%d%H", time.gmtime(now))
        item = RawItem(
            connector_id="canary",
            source_item_id=f"{parts.fqdn}:{bucket}",
            fetched_at=utcnow(),
            url=None,
            payload={
                "indicators": [{"type": "domain", "value": parts.fqdn}],
                "signal": "canary",
                "intel": {"source": "canary", "confirmed": True},
                "context": {"variant": variant, "hour": bucket},
            },
            project_ids=(rules.project,),
        )
        try:
            await deps.forward(item)
        except Exception as e:
            beacons.pop(parts.fqdn, None)
            log.warning("金丝雀转交失败：%s", type(e).__name__)
        return gif()

    @app.post(prefix + "/report", status_code=202)
    async def report(request: Request) -> Response:
        length = request.headers.get("content-length")
        if length is not None and length.isdigit() and int(length) > MAX_BODY:
            raise HTTPException(413, "payload too large")
        chunks = bytearray()
        async for chunk in request.stream():
            if len(chunks) + len(chunk) > MAX_BODY:
                raise HTTPException(413, "payload too large")
            chunks.extend(chunk)
        body = bytes(chunks)
        ts = request.headers.get("x-opti-timestamp", "")
        sig = request.headers.get("x-opti-signature", "")
        now = deps.clock()
        if not re.fullmatch(r"[0-9]{1,20}", ts) or abs(now - int(ts)) > MAX_SKEW:
            raise HTTPException(401, "missing or stale timestamp")
        expected = hmac.new(deps.report_key, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        if not re.fullmatch(r"[0-9a-f]{64}", sig) or not hmac.compare_digest(expected, sig):
            raise HTTPException(401, "bad signature")
        _prune(signatures, now, 2 * MAX_SKEW)
        if sig in signatures:
            raise HTTPException(409, "replayed")
        if len(signatures) >= _TRACKED_MAX:
            raise HTTPException(503, "retry later")
        try:
            data = ReportIn.model_validate_json(body)
        except ValidationError as e:
            raise HTTPException(422, "invalid report") from e
        report_id = uuid.uuid4().hex
        urls = [u for u in (normalize_url(x) for x in data.urls) if u is not None]
        rules, _, matcher = view()
        brand = any(hit.role == "match" for hit in matcher.match(data.description))
        item = RawItem(
            connector_id="public_report",
            source_item_id=report_id,
            fetched_at=utcnow(),
            url=None,
            payload={
                "indicators": [{"type": "report", "value": report_id}]
                + [{"type": "url", "value": u} for u in urls],
                "signal": "reported",
                "intel": {"source": "public_report", "confirmed": False},
                "context": {
                    "description": data.description,
                    "category": data.category,
                    "contact": data.contact,  # 个人信息：默认 90 天后清除（Task 9）
                    "observed_at": data.observed_at,
                    "lang": data.lang,
                    "brand_mentioned": brand,
                    "received_at": utcnow().isoformat(),
                },
            },
            project_ids=(rules.project,),
        )
        if len(json.dumps(item.payload["context"], ensure_ascii=False).encode()) > 16 * 1024:
            raise HTTPException(422, "report context too large")
        # Reserve before yielding, so simultaneous signed requests cannot race.
        signatures[sig] = now
        try:
            await deps.forward(item)
        except Exception as e:
            signatures.pop(sig, None)
            log.warning("公众举报转交失败：%s", type(e).__name__)
            raise HTTPException(503, "retry later") from None
        return JSONResponse({"id": report_id}, status_code=202)

    return app
