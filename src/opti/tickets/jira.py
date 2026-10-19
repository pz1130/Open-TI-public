"""Jira Cloud 工单（REST v3，设计 2026-10-16）：label 去重、ADF 正文、后续批次追加评论。"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from opti.alerting.views import AlertView
from opti.sdk.http import HttpError, RateLimitedHttpClient
from opti.tickets.client import PushResult, clean_ref
from opti.tickets.config import JiraConfig
from opti.tickets.content import comment_content, issue_content, title, to_adf
from opti.tickets.remote import HttpFactory, TicketRemoteError, classify, require_2xx

SUMMARY_LIMIT = 250
# 只认问题键：数字会被 Jira 当成 issue id，切换方式前留下的编号可能指向无关问题
ISSUE_KEY = re.compile(r"[A-Z][A-Z0-9_]+-[0-9]+")


class JiraTicketClient:
    name = "jira"

    def __init__(
        self,
        cfg: JiraConfig,
        api_token: str,
        *,
        include_accounts: bool,
        http_factory: HttpFactory,
    ) -> None:
        self._cfg = cfg
        self._include_accounts = include_accounts
        self._factory = http_factory
        basic = base64.b64encode(f"{cfg.email}:{api_token}".encode()).decode()
        self._headers = {"Authorization": f"Basic {basic}", "Accept": "application/json"}

    def __repr__(self) -> str:  # 不让令牌出现在日志与异常里
        return f"JiraTicketClient({self._cfg.base_url}, {self._cfg.project_key})"

    async def _call(
        self,
        http: RateLimitedHttpClient,
        method: str,
        path: str,
        *,
        json: Any = None,
        max_retries: int | None = None,
    ) -> Any:
        url = self._cfg.base_url + path
        resp = await http.request_json(
            method, url, headers=self._headers, json=json, max_retries=max_retries
        )
        require_2xx(resp, url)
        try:
            return resp.json()
        except ValueError:
            return None

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
                    if not ISSUE_KEY.fullmatch(existing_ref):
                        raise TicketRemoteError(
                            self._cfg.base_url, None, "rejected",
                            detail="linked ticket is not a Jira issue key",
                        )  # fmt: skip
                    await self._comment(http, existing_ref, view, extra)
                    return PushResult(existing_ref, self.name)
                ref = await self._find(http, key) or await self._create(http, key, view, extra)
            except HttpError as e:
                raise classify(e, "jira") from e
        return PushResult(ref, self.name)

    async def _find(self, http: RateLimitedHttpClient, key: str) -> str | None:
        """上次建单成功但本地事务失败时，重试不重复建单（搜索索引有秒级延迟）。"""
        jql = f'project = "{self._cfg.project_key}" AND labels = "{key}"'
        doc = await self._call(
            http, "POST", "/rest/api/3/search/jql",
            json={"jql": jql, "fields": ["key"], "maxResults": 1},
        )  # fmt: skip
        issues = doc.get("issues") if isinstance(doc, dict) else None
        if isinstance(issues, list) and issues and isinstance(issues[0], dict):
            return clean_ref(issues[0].get("key"))
        return None

    async def _create(
        self,
        http: RateLimitedHttpClient,
        key: str,
        view: AlertView,
        extra: Mapping[str, Any] | None,
    ) -> str | None:
        cfg = self._cfg
        fields: dict[str, Any] = dict(cfg.extra_fields)
        labels = [str(x) for x in fields.get("labels") or []]
        fields.update(
            project={"key": cfg.project_key},
            issuetype={"name": cfg.issue_type},
            summary=title(view, SUMMARY_LIMIT),
            description=to_adf(issue_content(view, extra, include_accounts=self._include_accounts)),
            labels=[*dict.fromkeys([*labels, key])],
        )
        priority = {s.value: name for s, name in cfg.priority_map.items()}.get(view.severity)
        if priority:
            fields["priority"] = {"name": priority}
        # 建单不重试：超时后对方可能已建单，交给下一轮查重
        doc = await self._call(
            http, "POST", "/rest/api/3/issue", json={"fields": fields}, max_retries=0
        )
        return clean_ref(doc.get("key")) if isinstance(doc, dict) else None

    async def _comment(
        self,
        http: RateLimitedHttpClient,
        ref: str,
        view: AlertView,
        extra: Mapping[str, Any] | None,
    ) -> None:
        body = to_adf(comment_content(view, extra, include_accounts=self._include_accounts))
        await self._call(
            http, "POST", f"/rest/api/3/issue/{quote(ref, safe='')}/comment",
            json={"body": body}, max_retries=0,
        )  # fmt: skip

    async def check(self) -> None:
        """测试连接：认证有效、项目存在且有配置的问题类型。"""
        async with self._factory() as http:
            try:
                await self._call(http, "GET", "/rest/api/3/myself")
                project = await self._call(
                    http, "GET", f"/rest/api/3/project/{quote(self._cfg.project_key, safe='')}"
                )
            except HttpError as e:
                raise classify(e, "jira") from e
        types = project.get("issueTypes") if isinstance(project, dict) else None
        names = {t.get("name") for t in types or [] if isinstance(t, dict)}
        if self._cfg.issue_type not in names:
            raise TicketRemoteError(self._cfg.base_url, None, "rejected", fields=("issuetype",))
