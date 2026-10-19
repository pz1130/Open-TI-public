"""限速 HTTP 客户端（设计文档 5.4）：令牌桶、重试与退避、统一 User-Agent、代理。

连接器必须通过 ctx.http() 使用它，不得自行创建 HTTP 客户端（设计文档 5.5）。
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from opti.core.secret_guard import SecretEgressBlocked, assert_no_secret, mask_text

Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]


def default_user_agent() -> str:
    from importlib.metadata import PackageNotFoundError, version

    from opti.organization import current_organization

    try:
        v = version("opti")
    except PackageNotFoundError:
        v = "dev"
    return current_organization().user_agent(v)


DEFAULT_USER_AGENT = default_user_agent()  # 沙箱容器在启动时取一次
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_DECODED_HEADERS = frozenset({"content-encoding", "content-length", "transfer-encoding"})
ERROR_BODY_BYTES = 16 * 1024
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


class HttpError(Exception):
    def __init__(
        self, url: str, status: int | None, message: str, *, body: bytes | None = None
    ) -> None:
        super().__init__(f"{message}（{status if status is not None else '网络错误'}）：{url}")
        self.url = url
        self.status = status
        self.body = body  # 仅 request_json：出错响应的前 16 KB，供解析错误字段


class TokenBucket:
    def __init__(
        self,
        rate: float,
        burst: float = 1.0,
        *,
        clock: Clock = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate 必须大于 0")
        self._rate = rate
        self._capacity = max(burst, 1.0)
        self._tokens = self._capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = self._clock()
                self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await self._sleep((1 - self._tokens) / self._rate)


@dataclass(frozen=True)
class HttpPolicy:
    user_agent: str = field(default_factory=default_user_agent)
    timeout: float = 30.0
    max_retries: int = 3
    backoff_base: float = 1.0
    backoff_max: float = 60.0
    per_host_rate: float = 1.0  # 每个目标主机每秒请求数
    per_host_burst: float = 3.0
    connector_rate: float | None = None  # 来自 manifest 套餐的速率限制
    max_body_bytes: int = 100 * 1024 * 1024
    persist_cookies: bool = False  # 默认不保存 Cookie（设计文档 2.2、2.8）
    proxy: str | None = None  # 仅用于网络出口隔离，不用于规避封禁（设计文档 2.4）


class RateLimitedHttpClient:
    def __init__(
        self,
        policy: HttpPolicy | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Clock = time.monotonic,
        sleep: Sleep = asyncio.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self.policy = policy or HttpPolicy()
        self._client = httpx.AsyncClient(
            timeout=self.policy.timeout,
            headers={"User-Agent": self.policy.user_agent},
            transport=transport,
            proxy=self.policy.proxy,
            follow_redirects=True,
        )
        self._clock = clock
        self._sleep = sleep
        self._rng = rng
        self._hosts: dict[str, TokenBucket] = {}
        self._connector = (
            TokenBucket(self.policy.connector_rate, 1.0, clock=clock, sleep=sleep)
            if self.policy.connector_rate
            else None
        )

    async def __aenter__(self) -> RateLimitedHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _bucket(self, host: str) -> TokenBucket:
        if host not in self._hosts:
            self._hosts[host] = TokenBucket(
                self.policy.per_host_rate,
                self.policy.per_host_burst,
                clock=self._clock,
                sleep=self._sleep,
            )
        return self._hosts[host]

    def _backoff(self, attempt: int) -> float:
        base = min(self.policy.backoff_max, self.policy.backoff_base * 2.0**attempt)
        return base * (0.5 + self._rng() / 2)

    def _retry_after(self, resp: httpx.Response) -> float | None:
        value = resp.headers.get("Retry-After")
        if not value:
            return None
        try:
            seconds = float(value)
        except ValueError:
            try:
                seconds = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
            except (TypeError, ValueError):
                return None
        return max(0.0, min(seconds, self.policy.backoff_max))

    async def _read(
        self, raw: httpx.Response, url: str, limit: int, truncate: bool
    ) -> httpx.Response:
        """边读边计数，超过上限就停：可疑站点可以返回无限长的响应体，不能先全部读进内存。"""
        chunks: list[bytes] = []
        size = 0
        async for chunk in raw.aiter_bytes():
            if size + len(chunk) > limit:
                if not truncate:
                    raise HttpError(url, raw.status_code, "响应体超过上限")
                chunks.append(chunk[: limit - size])
                break
            chunks.append(chunk)
            size += len(chunk)
        # aiter_bytes 已解压，新响应去掉编码与长度头，避免再次解压。
        headers = [
            (k, v) for k, v in raw.headers.multi_items() if k.lower() not in _DECODED_HEADERS
        ]
        return httpx.Response(
            raw.status_code,
            headers=headers,
            content=b"".join(chunks),
            request=raw.request,
            history=raw.history,
        )

    async def _error_body(self, raw: httpx.Response) -> bytes | None:
        chunks = bytearray()
        try:
            async for chunk in raw.aiter_bytes():
                chunks.extend(chunk[: ERROR_BODY_BYTES - len(chunks)])
                if len(chunks) >= ERROR_BODY_BYTES:
                    break
        except httpx.HTTPError:
            return None
        return bytes(chunks)

    async def _send(
        self,
        method: str,
        url: str,
        *,
        max_retries: int | None = None,
        max_body_bytes: int | None = None,
        truncate_body: bool = False,
        keep_error_body: bool = False,
        **kwargs: Any,
    ) -> httpx.Response:
        try:
            assert_no_secret(
                "http",
                url=url,
                params=kwargs.get("params"),
                body=[kwargs.get(k) for k in ("json", "data", "content")],
                headers=kwargs.get("headers"),
            )
        except SecretEgressBlocked as exc:  # 设计文档 2.3：发现的凭据永不外发、永不用于认证
            raise HttpError(mask_text(url), None, f"已拦截外发请求（{exc.reason}）") from exc
        host = httpx.URL(url).host
        last = self.policy.max_retries if max_retries is None else max_retries
        limit = self.policy.max_body_bytes if max_body_bytes is None else max_body_bytes
        for attempt in range(last + 1):
            if self._connector is not None:
                await self._connector.acquire()
            await self._bucket(host).acquire()
            delay: float | None = None
            try:
                async with self._client.stream(method, url, **kwargs) as raw:
                    if raw.status_code in RETRY_STATUS and attempt < last:
                        retry_after = self._retry_after(raw)
                        delay = retry_after if retry_after is not None else self._backoff(attempt)
                    elif raw.status_code >= 400:
                        body = await self._error_body(raw) if keep_error_body else None
                        raise HttpError(url, raw.status_code, "HTTP 错误", body=body)
                    else:
                        return await self._read(raw, url, limit, truncate_body)
            except httpx.HTTPError as e:
                if attempt == last:
                    raise HttpError(url, None, f"请求失败：{type(e).__name__}") from e
                delay = self._backoff(attempt)
            finally:
                if not self.policy.persist_cookies:
                    self._client.cookies.clear()
            await self._sleep(delay)
        raise AssertionError("unreachable")

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        extensions: Mapping[str, Any] | None = None,
        follow_redirects: bool | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        max_body_bytes: int | None = None,
        truncate_body: bool = False,
    ) -> httpx.Response:
        # extensions / follow_redirects：网页探测把连接钉在已检查的地址上，并自行跟随重定向。
        # timeout / max_retries：探测使用自己的超时，且不能按 API 客户端重试 5xx。
        # max_body_bytes / truncate_body：探测只需要页面开头，超出部分截断而不是报错。
        kwargs: dict[str, Any] = {"params": params, "headers": headers}
        if extensions is not None:
            kwargs["extensions"] = extensions
        if follow_redirects is not None:
            kwargs["follow_redirects"] = follow_redirects
        if timeout is not None:
            kwargs["timeout"] = timeout
        return await self._send(
            "GET",
            url,
            max_retries=max_retries,
            max_body_bytes=max_body_bytes,
            truncate_body=truncate_body,
            **kwargs,
        )

    async def post_json(
        self,
        url: str,
        payload: Any,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """用于推送告警、调用平台内部服务（截图沙箱）；不用于采集。"""
        kwargs: dict[str, Any] = {"json": payload, "headers": headers}
        if timeout is not None:
            kwargs["timeout"] = timeout
        return await self._send("POST", url, **kwargs)

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json: Any = None,
        params: Mapping[str, str] | None = None,
        max_retries: int | None = None,
    ) -> httpx.Response:
        """调用第三方系统 API（Jira、ServiceNow）：不跟随重定向（认证头不随跳转外发）；
        出错时 HttpError.body 保留响应体前 16 KB。建单等非幂等请求由调用方传 max_retries=0。"""
        kwargs: dict[str, Any] = {"headers": headers, "params": params, "follow_redirects": False}
        if json is not None:
            kwargs["json"] = json
        return await self._send(
            method, url, max_retries=max_retries, keep_error_body=True, **kwargs
        )

    async def post_form(
        self, url: str, data: Mapping[str, str], *, headers: Mapping[str, str] | None = None
    ) -> httpx.Response:
        """OAuth 客户端凭据认证；不用于采集，不跟随重定向泄露凭据。"""
        return await self._send(
            "POST",
            url,
            data=dict(data),
            headers=headers,
            max_retries=1,
            follow_redirects=False,
        )

    async def malwarebazaar_recent(self, auth_key: str) -> httpx.Response:
        """Only the read-only recent-metadata query; never expose arbitrary sample API commands."""
        return await self._send(
            "POST",
            MALWAREBAZAAR_API,
            data={"query": "get_recent", "selector": "time"},
            headers={"Auth-Key": auth_key, "Accept": "application/json"},
            follow_redirects=False,
            max_retries=0,
            max_body_bytes=4 * 1024 * 1024,
        )

    async def post_bytes(
        self,
        url: str,
        content: bytes,
        *,
        headers: Mapping[str, str],
        timeout: float | None = None,
    ) -> httpx.Response:
        """签名推送（工单 Webhook）：签名覆盖的就是发出的字节，不能交给 httpx 重新序列化。"""
        kwargs: dict[str, Any] = {
            "content": content,
            "headers": headers,
            "follow_redirects": False,
            "max_retries": 0,
        }
        if timeout is not None:
            kwargs["timeout"] = timeout
        return await self._send("POST", url, **kwargs)
