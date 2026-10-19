"""ServiceNow 工单（Table API，设计 2026-10-16）：correlation_id 去重、work_notes 追加后续批次。

认证：Basic（集成账号）或 OAuth client_credentials（令牌缓存在客户端内存，到期前 60 秒刷新，401 时刷新重试一次）。
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote

from opti.alerting.views import AlertView
from opti.sdk.http import HttpError, RateLimitedHttpClient
from opti.tickets.client import PushResult, clean_ref
from opti.tickets.config import ServiceNowConfig
from opti.tickets.content import comment_content, issue_content, title, to_text
from opti.tickets.remote import HttpFactory, TicketRemoteError, classify, require_2xx

SHORT_DESCRIPTION_LIMIT = 160
TOKEN_MARGIN_SECONDS = 60
DEFAULT_TOKEN_SECONDS = 1800


class ServiceNowTicketClient:
    name = "servicenow"

    def __init__(
        self,
        cfg: ServiceNowConfig,
        *,
        secret: str,
        include_accounts: bool,
        http_factory: HttpFactory,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """secret：auth=basic 时为密码，auth=oauth 时为 client_secret。"""
        self._cfg = cfg
        self._secret = secret
        self._include_accounts = include_accounts
        self._factory = http_factory
        self._clock = clock
        self._token: tuple[str, float] | None = None  # (access_token, 到期的单调时间)
        self._table = f"/api/now/table/{cfg.table}"

    def __repr__(self) -> str:  # 不让密码与令牌出现在日志与异常里
        return f"ServiceNowTicketClient({self._cfg.base_url}, {self._cfg.table})"

    async def _authorization(self, http: RateLimitedHttpClient, *, refresh: bool = False) -> str:
        cfg = self._cfg
        if cfg.auth == "basic":
            basic = base64.b64encode(f"{cfg.username}:{self._secret}".encode()).decode()
            return f"Basic {basic}"
        now = self._clock()
        if not refresh and self._token is not None and self._token[1] > now:
            return f"Bearer {self._token[0]}"
        url = f"{cfg.base_url}/oauth_token.do"
        resp = await http.post_form(
            url,
            {"grant_type": "client_credentials", "client_id": cfg.client_id or "",
             "client_secret": self._secret},
            headers={"Accept": "application/json"},
        )  # fmt: skip
        require_2xx(resp, url)
        try:
            doc = resp.json()
        except ValueError:
            doc = None
        token = doc.get("access_token") if isinstance(doc, dict) else None
        if not isinstance(token, str) or not token:
            raise TicketRemoteError(url, resp.status_code, "auth")
        raw_expires = doc.get("expires_in") if isinstance(doc, dict) else None
        expires = raw_expires if isinstance(raw_expires, int) else DEFAULT_TOKEN_SECONDS
        self._token = (token, now + max(0, expires - TOKEN_MARGIN_SECONDS))
        return f"Bearer {token}"

    async def _call(
        self,
        http: RateLimitedHttpClient,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, str] | None = None,
        max_retries: int | None = None,
    ) -> Any:
        url = self._cfg.base_url + path

        async def send(refresh: bool) -> Any:
            headers = {
                "Authorization": await self._authorization(http, refresh=refresh),
                "Accept": "application/json",
            }
            return await http.request_json(
                method, url, headers=headers, json=json, params=params, max_retries=max_retries
            )

        try:
            resp = await send(False)
        except HttpError as e:
            if e.status != 401 or self._cfg.auth != "oauth":
                raise
            self._token = None  # 令牌被提前吊销：刷新后重试一次（401 时对方没有建单）
            resp = await send(True)
        require_2xx(resp, url)
        try:
            doc = resp.json()
        except ValueError:
            return None
        return doc.get("result") if isinstance(doc, dict) else None

    async def push(
        self,
        view: AlertView,
        extra: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
        existing_ref: str | None = None,
    ) -> PushResult:
        key = idempotency_key or f"opti-alert-{view.alert_id}"
        async with self._factory() as http:
            try:
                if existing_ref:
                    await self._comment(http, existing_ref, view, extra)
                    return PushResult(existing_ref, self.name)
                ref = await self._find(http, key) or await self._create(http, key, view, extra)
            except HttpError as e:
                raise classify(e, "servicenow") from e
        return PushResult(ref, self.name)

    async def _query_one(
        self, http: RateLimitedHttpClient, field: str, value: str
    ) -> dict[str, Any] | None:
        """按字段等值查一条。表上没有该字段时 ServiceNow 可能忽略条件、返回无关记录，所以再核对一次。"""
        fields = "number,sys_id" if field == "number" else f"number,sys_id,{field}"
        rows = await self._call(
            http, "GET", self._table,
            params={"sysparm_query": f"{field}={value}", "sysparm_fields": fields, "sysparm_limit": "1"},
        )  # fmt: skip
        row = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
        return row if row is not None and row.get(field) == value else None

    async def _find(self, http: RateLimitedHttpClient, key: str) -> str | None:
        """上次建单成功但本地事务失败时，重试不重复建单。key 只含字母、数字与连字符。"""
        row = await self._query_one(http, "correlation_id", key)
        return clean_ref(row.get("number")) if row else None

    async def _create(
        self,
        http: RateLimitedHttpClient,
        key: str,
        view: AlertView,
        extra: Mapping[str, Any] | None,
    ) -> str | None:
        cfg = self._cfg
        body: dict[str, Any] = dict(cfg.extra_fields)
        body.update(
            short_description=title(view, SHORT_DESCRIPTION_LIMIT),
            description=to_text(
                issue_content(view, extra, include_accounts=self._include_accounts)
            ),
            correlation_id=key,
            correlation_display="Open-TI",
        )
        level = {s.value: v for s, v in cfg.urgency_impact_map.items()}.get(view.severity)
        if level is not None:
            body.update(urgency=str(level.urgency), impact=str(level.impact))
        # 建单不重试：超时后对方可能已建单，交给下一轮查重
        row = await self._call(
            http, "POST", self._table, json=body,
            params={"sysparm_fields": "number,sys_id"}, max_retries=0,
        )  # fmt: skip
        return clean_ref(row.get("number")) if isinstance(row, dict) else None

    async def _comment(
        self,
        http: RateLimitedHttpClient,
        ref: str,
        view: AlertView,
        extra: Mapping[str, Any] | None,
    ) -> None:
        # ticket_ref 只允许 [A-Za-z0-9._#/:-]，不含编码查询的 ^ 分隔符
        row = await self._query_one(http, "number", ref)
        sys_id = row.get("sys_id") if row else None
        if not isinstance(sys_id, str) or not sys_id:
            raise TicketRemoteError(self._cfg.base_url + self._table, 404, "rejected",
                                    detail="ticket not found")  # fmt: skip
        notes = to_text(comment_content(view, extra, include_accounts=self._include_accounts))
        await self._call(
            http, "PATCH", f"{self._table}/{quote(sys_id, safe='')}",
            json={"work_notes": notes}, params={"sysparm_fields": "number"}, max_retries=0,
        )  # fmt: skip

    async def check(self) -> None:
        """测试连接：认证有效（OAuth 能取到令牌）、能读取目标表，且表上有 correlation_id（继承 task）。"""
        async with self._factory() as http:
            try:
                rows = await self._call(
                    http, "GET", self._table,
                    params={"sysparm_limit": "1", "sysparm_fields": "number,correlation_id"},
                )  # fmt: skip
            except HttpError as e:
                raise classify(e, "servicenow") from e
        # 表为空时无法判断；有记录但不返回 correlation_id，说明该表没有这个字段
        first = rows[0] if isinstance(rows, list) and rows else None
        if isinstance(first, dict) and "correlation_id" not in first:
            raise TicketRemoteError(
                self._cfg.base_url + self._table, None, "rejected",
                fields=("correlation_id",), detail="table must extend task",
            )  # fmt: skip
