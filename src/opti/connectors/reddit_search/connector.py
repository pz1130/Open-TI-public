"""按获批用途检索公开 Reddit 帖子；只回传命中帖文供下游提取片段。"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from opti.core.documents import document_payload
from opti.core.feeds import parse_date, strip_html
from opti.core.text_match import TextMatcher
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

AUTH_URL = "https://www.reddit.com/api/v1/access_token"
API_URL = "https://oauth.reddit.com/search"
OVERLAP = timedelta(hours=1)
_ID = re.compile(r"[a-z0-9]{3,16}$")
_FULLNAME = re.compile(r"t3_[a-z0-9]{3,16}$")


def _post(data: Any) -> tuple[str, str, datetime, str] | None:
    if not isinstance(data, dict):
        return None
    post_id = data.get("id")
    if not isinstance(post_id, str) or not _ID.fullmatch(post_id):
        return None
    if data.get("name") != f"t3_{post_id}":
        return None
    if data.get("removed_by_category") or data.get("is_robot_indexable") is False:
        return None
    created = data.get("created_utc")
    if isinstance(created, bool) or not isinstance(created, int | float):
        return None
    try:
        published = datetime.fromtimestamp(created, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    title = strip_html(str(data.get("title") or ""))[:500]
    body = str(data.get("selftext") or "")[:20_000]
    if body in {"[removed]", "[deleted]"}:
        body = ""
    text = "\n".join(part for part in (title, body) if part)
    if not text:
        return None
    subreddit = data.get("subreddit")
    source = f"Reddit r/{subreddit[:80]}" if isinstance(subreddit, str) and subreddit else "Reddit"
    return post_id, text, published, source


class RedditSearchConnector(BaseConnector):
    id: ClassVar[str] = "reddit_search"
    tier: ClassVar[Tier] = Tier.FREEMIUM

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._access_token: str | None = None
        self._token_expires_at = 0.0
        public_sets = {
            name: ts.model_copy(update={"terms": terms})
            for name, ts in ctx.rules.sets.items()
            if ts.type != "executive" and not ts.private
            if (terms := tuple(term for term in ts.terms if term.remote_search))
        }
        self._matcher = TextMatcher(ctx.rules.model_copy(update={"sets": public_sets}))

    def validate_config(self) -> None:
        if not self.ctx.secret("client_id") or not self.ctx.secret("client_secret"):
            raise MissingCredential("需要已获批的 Reddit OAuth 客户端凭据")
        agent = self.config.get("user_agent")
        if not isinstance(agent, str) or len(agent.strip()) < 10 or any(c in agent for c in "\r\n"):
            raise ValueError("Reddit user_agent 必须是机构登记的描述性标识")

    async def _token(self) -> str:
        if self._access_token and time.monotonic() < self._token_expires_at:
            return self._access_token
        client_id = self.ctx.secret("client_id") or ""
        client_secret = self.ctx.secret("client_secret") or ""
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        response = await self.ctx.http().post_form(
            AUTH_URL,
            {"grant_type": "client_credentials"},
            headers={
                "Authorization": f"Basic {basic}",
                "User-Agent": str(self.config["user_agent"]),
            },
        )
        data = response.json()
        token = data.get("access_token") if isinstance(data, dict) else None
        expires = data.get("expires_in") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token or not isinstance(expires, int | float):
            raise ValueError("Reddit OAuth 响应缺少有效令牌或过期时间")
        self._access_token = token
        self._token_expires_at = time.monotonic() + max(0.0, float(expires) - 60.0)
        return token

    async def _search(self, query: str, after: str | None) -> dict[str, Any]:
        token = await self._token()
        params = {"q": query, "sort": "new", "t": "week", "limit": "100", "type": "link",
                  "raw_json": "1"}  # fmt: skip
        if after:
            params["after"] = after
        headers = {"Authorization": f"Bearer {token}", "User-Agent": str(self.config["user_agent"])}
        url = API_URL
        try:
            response = await self.ctx.http().get(
                url,
                params=params,
                headers=headers,
                follow_redirects=False,
                max_body_bytes=8 * 1024 * 1024,
            )
        except HttpError as exc:
            if exc.status != 401:
                raise
            self._access_token = None
            headers["Authorization"] = f"Bearer {await self._token()}"
            response = await self.ctx.http().get(
                url,
                params=params,
                headers=headers,
                follow_redirects=False,
                max_body_bytes=8 * 1024 * 1024,
            )
        data = response.json()
        listing = data.get("data") if isinstance(data, dict) else None
        if not isinstance(listing, dict) or not isinstance(listing.get("children"), list):
            raise ValueError("Reddit 搜索响应不是 Listing")
        return listing

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        seen: set[str] = set()
        for term in plan.terms[: int(self.config.get("max_queries", 5))]:
            if len(term.value) > 490:
                continue
            query = f'"{term.value}"'
            key = "since:" + hashlib.sha256(query.encode()).hexdigest()[:16]
            since = parse_date(self.ctx.get_cursor(key))
            newest = since
            after: str | None = None
            complete = True
            for _ in range(int(self.config.get("max_pages", 2))):
                try:
                    listing = await self._search(query, after)
                except (HttpError, ValueError) as exc:
                    self.ctx.logger().warning("Reddit 搜索失败：%s", type(exc).__name__)
                    complete = False
                    break
                for child in listing["children"]:
                    if not isinstance(child, dict) or child.get("kind") != "t3":
                        continue
                    parsed = _post(child.get("data"))
                    if parsed is None:
                        continue
                    post_id, body, published, source = parsed
                    if since is not None and published < since - OVERLAP:
                        continue
                    if newest is None or published > newest:
                        newest = published
                    if post_id in seen or not any(
                        hit.role == "match" for hit in self._matcher.match(body)
                    ):
                        continue
                    seen.add(post_id)
                    url = f"https://www.reddit.com/comments/{post_id}"
                    yield RawItem(
                        connector_id=self.id,
                        source_item_id=f"t3_{post_id}",
                        fetched_at=utcnow(),
                        url=url,
                        payload=document_payload(
                            url=url,
                            title="Reddit 公开帖子",
                            text=body,
                            published_at=published,
                            source_name=source,
                        ),
                        project_ids=plan.project_ids,
                    )
                next_page = listing.get("after")
                after = (
                    next_page
                    if isinstance(next_page, str) and _FULLNAME.fullmatch(next_page)
                    else None
                )
                if after is None:
                    break
            else:
                if after is not None:
                    complete = False
                    self.ctx.logger().warning("Reddit 搜索达到分页上限，游标未推进：%s", query)
            if complete and newest is not None and newest != since:
                self.ctx.set_cursor(key, newest.isoformat())
