"""通过 GitLab 官方 Projects API 查找公开品牌相关项目。"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping
from datetime import datetime
from typing import Any, ClassVar

from opti.core.documents import document_payload
from opti.core.feeds import parse_date
from opti.core.secrets import redact_text
from opti.core.text_match import TextMatcher
from opti.sdk.base import BaseConnector
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API_URL = "https://gitlab.com/api/v4/projects"
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def _path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    parts = value.split("/")
    if not 2 <= len(parts) <= 10 or any(
        not _SEGMENT.fullmatch(part) or ".." in part for part in parts
    ):
        return None
    return value


def _project(raw: Any) -> tuple[int, str, str, str, datetime | None] | None:
    if not isinstance(raw, dict) or raw.get("visibility") != "public":
        return None
    project_id = raw.get("id")
    if isinstance(project_id, bool) or not isinstance(project_id, int) or project_id <= 0:
        return None
    path = _path(raw.get("path_with_namespace"))
    name = raw.get("name")
    if path is None or not isinstance(name, str):
        return None
    name = " ".join(name.split())[:500]
    if not name:
        return None
    description = raw.get("description")
    description = " ".join(description.split())[:2000] if isinstance(description, str) else ""
    return project_id, path, name, description, parse_date(raw.get("created_at"))


class GitLabProjectsConnector(BaseConnector):
    id: ClassVar[str] = "gitlab_projects"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        public_sets = {
            name: ts.model_copy(update={"terms": terms})
            for name, ts in ctx.rules.sets.items()
            if ts.type != "executive" and not ts.private
            if (terms := tuple(term for term in ts.terms if term.remote_search))
        }
        self._matcher = TextMatcher(ctx.rules.model_copy(update={"sets": public_sets}))

    def validate_config(self) -> None:
        excluded = self.config.get("exclude_namespaces") or []
        if not isinstance(excluded, list) or any(
            not isinstance(value, str) or not _SEGMENT.fullmatch(value) for value in excluded
        ):
            raise ValueError("GitLab exclude_namespaces 必须是命名空间名称列表")

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        seen: set[int] = set()
        excluded = {value.lower() for value in self.config.get("exclude_namespaces") or []}
        queries = list(
            dict.fromkeys(term.value for term in plan.terms if 1 < len(term.value) <= 100)
        )
        page_size = int(self.config.get("page_size", 20))
        for query in queries[: int(self.config.get("max_queries", 2))]:
            for page in range(1, int(self.config.get("max_pages", 1)) + 1):
                try:
                    response = await self.ctx.http().get(
                        API_URL,
                        params={
                            "search": query,
                            "visibility": "public",
                            "simple": "true",
                            "per_page": str(page_size),
                            "page": str(page),
                            "order_by": "created_at",
                            "sort": "desc",
                        },
                        follow_redirects=False,
                        max_retries=0,
                        max_body_bytes=2 * 1024 * 1024,
                    )
                    if response.status_code != 200:
                        raise ValueError("GitLab 项目搜索返回非成功状态")
                    projects = response.json()
                    if not isinstance(projects, list):
                        raise ValueError("GitLab 项目搜索响应不是列表")
                except (HttpError, ValueError) as exc:
                    self.ctx.logger().warning("GitLab 项目搜索失败：%s", type(exc).__name__)
                    break
                for raw in projects:
                    parsed = _project(raw)
                    if parsed is None:
                        continue
                    project_id, path, name, description, published = parsed
                    if project_id in seen or path.split("/", 1)[0].lower() in excluded:
                        continue
                    body = redact_text(f"{path}\n{name}\n{description}")
                    if not any(hit.role == "match" for hit in self._matcher.match(body)):
                        continue
                    seen.add(project_id)
                    url = f"https://gitlab.com/{path}"
                    yield RawItem(
                        connector_id=self.id,
                        source_item_id=f"project:{project_id}",
                        fetched_at=utcnow(),
                        url=url,
                        payload=document_payload(
                            url=url,
                            title="GitLab 公开项目候选",
                            text=body,
                            published_at=published,
                            source_name="GitLab.com",
                        ),
                        project_ids=plan.project_ids,
                    )
                next_page = response.headers.get("x-next-page")
                if next_page is not None:
                    if next_page != str(page + 1):
                        break
                elif len(projects) < page_size:
                    break
