"""人工 URL 提交（设计文档 4.2）：分析员提交线索，平台直接生成告警；平台名单检查只做本地匹配，不访问目标。"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import PlatformCheckOut, SubmissionIn, SubmissionOut
from opti.core.scoring import Category, Severity
from opti.pipeline import submissions
from opti.pipeline.submissions import Submission, SubmissionError

router = APIRouter(tags=["submissions"])
Triager = Annotated[Principal, Depends(require(Perm.ALERTS_TRIAGE))]


@router.get("/submissions/platform")
async def platform_check(
    request: Request, user: Triager, url: Annotated[str, Query(min_length=1, max_length=2048)]
) -> PlatformCheckOut:
    deps = get_deps(request)
    try:
        normalized, host, pid = submissions.check_url(url, deps.rules, deps.takedown)
    except SubmissionError as e:
        return PlatformCheckOut(
            url=None, platform=None, platform_name=None, fetch=False, error=str(e)
        )
    platform = deps.takedown.platform_for(host)
    return PlatformCheckOut(
        url=normalized,
        platform=pid,
        platform_name=platform.name if platform else None,
        fetch=platform is None,
        error=None,
    )


@router.post("/submissions", status_code=201)
async def create_submission(body: SubmissionIn, request: Request, user: Triager) -> SubmissionOut:
    deps = get_deps(request)
    sub = Submission(
        url=body.url,
        category=Category(body.category),
        severity=Severity(body.severity),
        description=body.description,
        observed_at=body.observed_at,
    )
    async with deps.sessions.begin() as s:
        try:
            result = await submissions.submit(
                s, sub, rules=deps.rules, cfg=deps.takedown, user_id=user.user_id, now=deps.clock()
            )
        except SubmissionError as e:
            raise HTTPException(422, str(e)) from e
        # 说明可能含个人信息，审计只记主机与选项
        await record(
            s,
            request,
            user,
            "submission.create",
            target_type="alert",
            target_id=result.alert_id,
            detail={
                "host": urlsplit(result.url).hostname,
                "category": body.category,
                "severity": body.severity,
                "platform": result.platform,
            },
        )
    return SubmissionOut(**asdict(result))
