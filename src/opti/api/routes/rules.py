"""关键词测试沙盒（设计文档 14）：用当前规则或粘贴的草稿测试域名与文本；草稿只校验、不保存。"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import DomainReportOut, RulesTestIn, RulesTestOut, TextHitOut
from opti.core.config import ConfigError, parse_project_rules
from opti.core.domain_match import DomainMatcher
from opti.core.report import domain_report
from opti.core.text_match import TextMatcher

router = APIRouter(tags=["rules"])
Tester = Annotated[Principal, Depends(require(Perm.RULES_TEST))]


@router.post("/rules/test")
async def test_rules(body: RulesTestIn, request: Request, user: Tester) -> RulesTestOut:
    deps = get_deps(request)
    rules, source = deps.rules, "current"
    draft = (body.draft_yaml or "").strip()
    if draft:
        try:
            rules = parse_project_rules(draft, source="草稿", allow_aliases=False)
        except ConfigError as e:
            raise HTTPException(422, detail={"message": str(e)}) from e
        source = "draft"
    matcher = DomainMatcher(rules.domains)
    reports = [
        DomainReportOut(**domain_report(matcher, d.strip())) for d in body.domains if d.strip()
    ]
    hits = TextMatcher(rules).match(body.text) if body.text else []
    detail: dict[str, Any] = {
        "source": source,
        "domains": len(reports),
        "text_chars": len(body.text),
    }
    if draft:
        detail["draft_sha256"] = hashlib.sha256(
            draft.encode("utf-8")
        ).hexdigest()  # 只记哈希，不记内容
    async with deps.sessions.begin() as s:
        await record(s, request, user, "rules.test", detail=detail)
    return RulesTestOut(
        source="draft" if draft else "current",
        project=rules.project,
        domains=reports,
        text_hits=[
            TextHitOut(
                set_name=h.set_name, term=h.term, mode=h.mode, role=h.role, context=h.context
            )
            for h in hits
        ],
    )
