"""Microsoft Graph 只读邮件客户端：Mail.Read；邮箱范围由管理员限定，不修改邮件。"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote, urlsplit

from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError, RateLimitedHttpClient

Clock = Callable[[], float]
_SELECT = "id,internetMessageId,subject,from,replyTo,receivedDateTime,hasAttachments,body,internetMessageHeaders"


class GraphError(Exception):
    def __init__(self, operation: str, status: int | None) -> None:
        super().__init__(
            f"Microsoft Graph {operation} 失败（{status if status is not None else '网络错误'}）"
        )
        self.status = status


class GraphMailClient:
    def __init__(
        self,
        http: RateLimitedHttpClient,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        authority: str = "https://login.microsoftonline.com",
        graph: str = "https://graph.microsoft.com/v1.0",
        clock: Clock = time.monotonic,
    ) -> None:
        for endpoint in (authority, graph):
            parts = urlsplit(endpoint)
            if (
                parts.scheme != "https"
                or not parts.hostname
                or parts.username
                or parts.query
                or parts.fragment
            ):
                raise ValueError("Graph/authority 必须是无凭据的 HTTPS 地址")
        self._http = http
        self._token_url = f"{authority.rstrip('/')}/{quote(tenant_id, safe='')}/oauth2/v2.0/token"
        self._scope = graph.rstrip("/").rsplit("/", 1)[0] + "/.default"
        self._graph = graph.rstrip("/")
        self._client_id, self._client_secret = client_id, client_secret
        self._clock = clock
        self._token: tuple[str, float] | None = None
        self.next_link: str | None = None

    async def _bearer(self) -> str:
        if self._token is not None and self._token[1] - self._clock() > 60:
            return self._token[0]
        try:
            resp = await self._http.post_form(
                self._token_url,
                {
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": self._scope,
                    "grant_type": "client_credentials",
                },
            )
            body = resp.json()
            token = body["access_token"]
            if resp.status_code != 200 or not isinstance(token, str) or not token:
                raise ValueError("invalid token")
            expires = float(body.get("expires_in", 3600))
        except HttpError as e:
            raise GraphError("取令牌", e.status) from None
        except (ValueError, TypeError, KeyError):
            raise GraphError("取令牌响应", None) from None
        self._token = (token, self._clock() + expires)
        return token

    async def _get(
        self, operation: str, url: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        # nextLink is opaque, but must stay in the configured Graph API. Never
        # send a mailbox token to a different origin or follow a redirect.
        if not url.startswith(self._graph + "/"):
            raise GraphError("分页地址", None)
        headers = {"Authorization": f"Bearer {await self._bearer()}"}
        try:
            resp = await self._http.get(
                url,
                params=params,
                headers=headers,
                follow_redirects=False,
                max_body_bytes=40 * 1024 * 1024,
            )
            if resp.status_code != 200:
                raise GraphError(operation, resp.status_code)
            data = resp.json()
            if not isinstance(data, dict):
                raise ValueError("invalid response")
            return data
        except HttpError as e:
            raise GraphError(operation, e.status) from None
        except (ValueError, TypeError):
            raise GraphError(operation + "响应", None) from None

    def _user(self, mailbox: str) -> str:
        return f"{self._graph}/users/{quote(mailbox, safe='')}"

    async def list_messages(
        self,
        mailbox: str,
        folder: str,
        *,
        since: str | None,
        top: int = 50,
        max_pages: int = 4,
        next_link: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, str] | None = {
            "$orderby": "receivedDateTime asc",
            "$top": str(top),
            "$select": _SELECT,
        }
        if since and params is not None:
            params["$filter"] = f"receivedDateTime ge {since}"
        url: str | None = (
            next_link or f"{self._user(mailbox)}/mailFolders/{quote(folder, safe='')}/messages"
        )
        if next_link:
            params = None
        out: list[dict[str, Any]] = []
        for _ in range(max_pages):
            if url is None:
                break
            data = await self._get("列出邮件", url, params)
            values = data.get("value")
            if not isinstance(values, list):
                raise GraphError("列出邮件响应", None)
            out.extend(m for m in values if isinstance(m, dict))
            url, params = self._next(data), None
        self.next_link = url
        return out

    @staticmethod
    def _next(data: Mapping[str, Any]) -> str | None:
        value = data.get("@odata.nextLink")
        if value is not None and not isinstance(value, str):
            raise GraphError("分页地址", None)
        return value or None

    async def attachments(self, mailbox: str, message_id: str) -> list[dict[str, Any]]:
        url: str | None = f"{self._user(mailbox)}/messages/{quote(message_id, safe='')}/attachments"
        out: list[dict[str, Any]] = []
        # Bound pathological responses; do not silently truncate attachments.
        for _ in range(100):
            if url is None:
                return out
            data = await self._get("读取附件", url)
            values = data.get("value")
            if not isinstance(values, list):
                raise GraphError("读取附件响应", None)
            out.extend(a for a in values if isinstance(a, dict))
            url = self._next(data)
        raise GraphError("附件分页超过上限", None)

    async def item_attachment(
        self, mailbox: str, message_id: str, attachment_id: str
    ) -> dict[str, Any]:
        url = f"{self._user(mailbox)}/messages/{quote(message_id, safe='')}/attachments/{quote(attachment_id, safe='')}"
        return await self._get(
            "读取项目附件", url, {"$expand": "microsoft.graph.itemattachment/item"}
        )


def graph_client(ctx: ConnectorContext, config: Mapping[str, Any]) -> GraphMailClient:
    return GraphMailClient(
        ctx.http(),
        tenant_id=ctx.secret("tenant_id") or "",
        client_id=ctx.secret("client_id") or "",
        client_secret=ctx.secret("client_secret") or "",
        authority=str(config.get("authority", "https://login.microsoftonline.com")),
        graph=str(config.get("graph", "https://graph.microsoft.com/v1.0")),
    )
