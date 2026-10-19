"""A saved keyword selection shared by platform and collector execution."""

from dataclasses import replace
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from opti.core.config import ProjectRules
from opti.sdk.models import QueryPlan
from opti.sdk.plan import build_query_plan

Scope = Literal["text", "domain"]


def node_rules_for_scan(rules: ProjectRules) -> dict[str, Any]:
    """Manual jobs need no personnel, private or local-only terms on the collector."""
    data = rules.model_dump(mode="json")
    sets: dict[str, Any] = {}
    for name, group in data["sets"].items():
        if group["type"] == "executive" or group["private"]:
            continue
        terms = [term for term in group["terms"] if term["remote_search"]]
        if terms:
            sets[name] = {**group, "terms": terms}
    return {**data, "sets": sets}


class KeywordScan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    project_id: str
    rules_version: int = Field(ge=0)
    scope: Scope
    term: str | None = None


def scan_plan(rules: ProjectRules, scan: KeywordScan) -> QueryPlan:
    if rules.project != scan.project_id:
        raise ValueError("扫描项目已变化，请刷新页面后重试")
    plan = build_query_plan(rules)
    if scan.scope == "text":
        terms = tuple(t for t in plan.terms if scan.term is None or t.value == scan.term)
        if not terms:
            raise ValueError("没有可扫描的已保存文本词；需要公开、允许外部检索的短语词")
        return replace(plan, terms=terms, brand_tokens=(), restricted_tokens=(), domains=())
    tokens = tuple(t for t in plan.brand_tokens if scan.term is None or t == scan.term)
    restricted = tuple(t for t in plan.restricted_tokens if scan.term is None or t[0] == scan.term)
    if not tokens and not restricted:
        raise ValueError("没有可扫描的已保存域名关键词，请先保存品牌词")
    return replace(plan, terms=(), brand_tokens=tokens, restricted_tokens=restricted)
