"""Jira / ServiceNow 共用：HTTP 客户端工厂与错误分类（设计 2026-10-16）。

每次推送新建一个 HTTP 客户端并在结束时关闭：工单量很小，这样配置（代理）变化时不用管旧连接的生命周期。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Literal

import httpx

from opti.core.secret_guard import mask_text
from opti.sdk.http import HttpError, HttpPolicy, RateLimitedHttpClient

ErrorKind = Literal["auth", "rejected", "unavailable"]
HttpFactory = Callable[[], RateLimitedHttpClient]
_REJECTED = frozenset({400, 404, 409, 422})


def http_factory(
    proxy: str | None, *, transport: httpx.AsyncBaseTransport | None = None, max_retries: int = 2
) -> HttpFactory:
    def make() -> RateLimitedHttpClient:
        policy = HttpPolicy(
            proxy=proxy,
            timeout=30.0,
            max_retries=max_retries,
            per_host_rate=5.0,
            per_host_burst=5.0,
        )
        return RateLimitedHttpClient(policy, transport=transport)

    return make


class TicketRemoteError(HttpError):
    """工单系统拒绝或不可用。继承 HttpError：现有 except HttpError 分支照常捕获。"""

    def __init__(
        self,
        url: str,
        status: int | None,
        kind: ErrorKind,
        *,
        fields: tuple[str, ...] = (),
        detail: str | None = None,
    ) -> None:
        super().__init__(url, status, f"ticket system {kind}")
        self.kind: ErrorKind = kind
        self.fields = fields
        self.detail = detail

    def public_message(self) -> str:
        if self.status is not None:
            status = f"HTTP {self.status}"
        else:  # 没有状态码：网络错误，或请求前就判定为拒绝
            status = "network error" if self.kind == "unavailable" else ""
        fields = f"({', '.join(self.fields)})" if self.fields else ""
        tail = " ".join(part for part in (status, fields, self.detail or "") if part)
        return f"ticket system {self.kind}: {tail}" if tail else f"ticket system {self.kind}"


def _json(body: bytes | None) -> object:
    try:
        return json.loads(body or b"")
    except ValueError:
        return None


def classify(exc: HttpError, system: Literal["jira", "servicenow"]) -> TicketRemoteError:
    if isinstance(exc, TicketRemoteError):
        return exc
    status = exc.status
    if status in (401, 403):
        return TicketRemoteError(exc.url, status, "auth")
    if status not in _REJECTED:
        return TicketRemoteError(exc.url, status, "unavailable")
    doc = _json(exc.body)
    fields: tuple[str, ...] = ()
    detail: str | None = None
    if system == "jira" and isinstance(doc, dict) and isinstance(doc.get("errors"), dict):
        fields = tuple(sorted(str(k) for k in doc["errors"]))[:20]  # 只取字段名，不取值
    if system == "servicenow" and isinstance(doc, dict) and isinstance(doc.get("error"), dict):
        message = doc["error"].get("message")
        detail = mask_text(str(message))[:200] if message else None
    return TicketRemoteError(exc.url, status, "rejected", fields=fields, detail=detail)


def require_2xx(resp: httpx.Response, url: str) -> None:
    """request_json 不跟随重定向：3xx 也算不可用。"""
    if not 200 <= resp.status_code < 300:
        raise TicketRemoteError(url, resp.status_code, "unavailable")
