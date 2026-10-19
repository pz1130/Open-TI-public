"""阻断列表与 STIX 2.1 导出：机器用 API Token，人工用登录会话。"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from opti.api.deps import current_user, get_deps, record
from opti.api.rbac import Perm
from opti.api.tokens import resolve_token
from opti.core.scoring import Severity
from opti.core.stix import build_bundle
from opti.export import stix as stix_export
from opti.export.blocklist import confirmed_entries, to_csv, to_rpz, to_txt

router = APIRouter(tags=["export"])
SCOPE = "blocklist:export"
STIX_SCOPE = "stix:export"


async def _export_actor(request: Request, scope: str, perm: Perm) -> str:
    deps = get_deps(request)
    auth = request.headers.get("Authorization")
    if auth is not None:
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(401, "invalid authorization header")
        async with deps.sessions.begin() as s:
            row = await resolve_token(s, token.strip(), scope, deps.clock())
            if row is None:
                raise HTTPException(401, "invalid, expired or revoked token")
            return f"token:{row.name}"
    user = await current_user(request)
    if perm not in user.perms:
        raise HTTPException(403, "forbidden")
    return user.username


async def blocklist_actor(request: Request) -> str:
    return await _export_actor(request, SCOPE, Perm.BLOCKLIST_EXPORT)


async def stix_actor(request: Request) -> str:
    return await _export_actor(request, STIX_SCOPE, Perm.STIX_EXPORT)


@router.get("/export/blocklist", response_class=Response)
async def export_blocklist(
    request: Request,
    actor: Annotated[str, Depends(blocklist_actor)],
    fmt: Annotated[Literal["txt", "csv", "rpz"], Query(alias="format")] = "txt",
    kind: Annotated[Literal["domain", "url"], Query(alias="type")] = "domain",
    days: Annotated[int, Query(ge=1, le=3650)] = 180,
) -> Response:
    deps = get_deps(request)
    now = deps.clock()
    async with deps.sessions.begin() as s:
        entries = await confirmed_entries(s, deps.rules, now=now, days=days)
        if fmt == "csv":
            text, media = to_csv(entries), "text/csv"
        elif fmt == "rpz":
            text, media = to_rpz(entries, now), "text/plain"
        else:
            text, media = to_txt(entries, kind), "text/plain"
        await record(
            s, request, actor, "export.blocklist",
            detail={"format": fmt, "type": kind, "days": days, "entries": len(entries)},
        )  # fmt: skip
    headers = {
        "Content-Disposition": f'attachment; filename="opti-blocklist.{fmt}"',
        "Cache-Control": "no-store",
    }
    return Response(text, media_type=f"{media}; charset=utf-8", headers=headers)


@router.get("/export/stix", response_class=Response)
async def export_stix(
    request: Request,
    actor: Annotated[str, Depends(stix_actor)],
    days: Annotated[int, Query(ge=1, le=3650)] = 30,
    min_severity: Annotated[Literal["low", "medium", "high", "critical"] | None, Query()] = None,
) -> Response:
    deps = get_deps(request)
    now = deps.clock()
    level = Severity(min_severity) if min_severity else deps.sharing.stix.min_severity
    async with deps.sessions.begin() as s:
        findings = await stix_export.collect(
            s, deps.rules, since=now - timedelta(days=days), min_severity=level
        )
        bundle = build_bundle(
            findings,
            project=deps.rules.project,
            organization=deps.organization.name,
            base_url=deps.public_base_url,
            tlp=deps.sharing.stix.tlp,
        )
        await record(
            s,
            request,
            actor,
            "export.stix",
            detail={
                "days": days,
                "min_severity": level.value,
                "findings": len(findings),
                "objects": len(bundle["objects"]),
            },
        )
    headers = {
        "Content-Disposition": 'attachment; filename="opti-stix.json"',
        "Cache-Control": "no-store",
    }
    return Response(
        json.dumps(bundle, ensure_ascii=False),
        media_type="application/stix+json;version=2.1",
        headers=headers,
    )
