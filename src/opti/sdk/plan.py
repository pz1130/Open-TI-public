"""从项目规则生成数据源无关的查询计划（设计文档 5.3）。"""

from __future__ import annotations

from datetime import datetime

from opti.core.config import ProjectRules
from opti.sdk.models import QueryPlan, SearchTerm


def build_query_plan(rules: ProjectRules, *, since: datetime | None = None) -> QueryPlan:
    terms = tuple(
        SearchTerm(t.value, "phrase")
        for _, ts in rules.sets_with_role("match")
        # 人员类与私密关键词不下发到外部数据源与境外节点（设计文档 2.5）
        if ts.type != "executive" and not ts.private
        for t in ts.terms
        if t.remote_search and t.mode == "phrase"
    )
    return QueryPlan(
        project_ids=(rules.project,),
        terms=terms,
        domains=rules.domains.official,
        brand_tokens=rules.domains.brand_tokens,
        restricted_tokens=tuple(rules.domains.restricted_tokens.items()),
        languages=rules.languages,
        since=since,
    )
