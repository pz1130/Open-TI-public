"""Find related public files with GitHub Code Search; redact snippets on the collector."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar
from urllib.parse import urlsplit

from opti.core.codehits import REPO_RE
from opti.core.secrets import redact_text
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow

API = "https://api.github.com"
MAX_FRAGMENTS = 3
FRAGMENT_CHARS = 300


class GithubCodeConnector(BaseConnector):
    id: ClassVar[str] = "github_code"
    tier: ClassVar[Tier] = Tier.FREE

    def __init__(self, ctx: ConnectorContext, config: Mapping[str, Any]) -> None:
        super().__init__(ctx, config)
        self._exclude = {str(o).lower() for o in config.get("exclude_owners") or []}

    def validate_config(self) -> None:
        if not self.ctx.secret("token"):
            raise MissingCredential(
                "需要 token（OPTI_SECRET_GITHUB_CODE_TOKEN，只需公开仓库只读权限）"
            )
        self._api_base()

    def _api_base(self) -> str:
        value = str(self.config.get("api_base", API)).rstrip("/")
        try:
            base = urlsplit(value)
        except ValueError as exc:
            raise ValueError("GitHub API 地址不合法") from exc
        if value != API or base.hostname != "api.github.com":
            raise ValueError("仅支持 GitHub 官方公开代码 API")
        return value

    def _terms(self) -> list[tuple[str, str]]:
        terms = [(d, "domain") for d in self.ctx.rules.domains.official]
        terms += [
            (str(t).strip(), "internal")
            for t in self.config.get("internal_terms") or []
            if str(t).strip()
        ]
        return list(dict.fromkeys(terms))[: int(self.config.get("max_queries", 10))]

    async def _search(self, query: str, page: int) -> list[Any]:
        base = self._api_base()
        response = await self.ctx.http().get(
            f"{base}/search/code",
            params={"q": query, "per_page": "100", "page": str(page)},
            headers={
                "Authorization": f"Bearer {self.ctx.secret('token') or ''}",
                "Accept": "application/vnd.github.text-match+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            follow_redirects=False,
        )
        document = response.json()
        if not isinstance(document, dict):
            return []
        items = document.get("items")
        return items if isinstance(items, list) else []

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        seen: set[str] = set()
        for term, kind in self._terms():
            query = f'"{term}"'
            for page in range(1, int(self.config.get("max_pages", 1)) + 1):
                try:
                    items = await self._search(query, page)
                except (HttpError, ValueError, AttributeError) as exc:
                    self.ctx.logger().warning("GitHub 代码搜索失败（%s）：%s", term, exc)
                    break
                for item in items:
                    hit = self._hit(item, term, kind)
                    if hit is None:
                        continue
                    key = f"{hit['repo']}:{hit['path']}:{hit['blob_sha']}"
                    if key in seen:
                        continue
                    seen.add(key)
                    yield RawItem(
                        connector_id=self.id,
                        source_item_id=key,
                        fetched_at=utcnow(),
                        url=hit["html_url"],
                        payload={"code_hit": hit},
                        project_ids=plan.project_ids,
                    )
                if len(items) < 100:
                    break

    def _hit(self, item: Any, term: str, kind: str) -> dict[str, Any] | None:
        if not isinstance(item, dict) or not isinstance(item.get("repository"), dict):
            return None
        info = item["repository"]
        repo = str(info.get("full_name") or "")
        if not REPO_RE.fullmatch(repo) or ".." in repo or info.get("private") is not False:
            return None
        if repo.split("/", 1)[0].lower() in self._exclude:
            return None
        html_url = str(item.get("html_url") or "")
        if not html_url.lower().startswith(f"https://github.com/{repo.lower()}/"):
            return None
        text_matches = item.get("text_matches")
        if not isinstance(text_matches, list):
            text_matches = []
        fragments = [
            redact_text(str(match.get("fragment") or ""))[:FRAGMENT_CHARS]
            for match in text_matches[:MAX_FRAGMENTS]
            if isinstance(match, dict) and match.get("fragment")
        ]
        return {
            "repo": repo,
            "path": str(item.get("path") or "")[:500],
            "html_url": html_url[:1000],
            "blob_sha": str(item.get("sha") or "")[:64],
            "term": term,
            "term_kind": kind,
            "fork": bool(info.get("fork")),
            "fragments": fragments,
        }
