"""监视列表『关键词』（设计 2026-10-15-domain-keywords）：管理关键词规则 domains 段的四类词。

每次增删都在最新规则版本上只改一项，经 config_store.store() 存为新版本（与配置页同一份数据）。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy import text as sql_text
from sqlalchemy.exc import DBAPIError

from opti.api import config_store
from opti.api.deps import Principal, get_deps, record, require
from opti.api.pagination import page_offset
from opti.api.rbac import Perm
from opti.api.schemas import (
    AffixesIn,
    BackfillOut,
    BackfillRunOut,
    DomainKeywordsOut,
    KeywordChangeOut,
    KeywordHitOut,
    KeywordHitPage,
    KeywordIn,
    KeywordKindIn,
    KeywordStatOut,
    RestrictedKeywordOut,
)
from opti.configs import kinds, revisions
from opti.core.config import ProjectRules
from opti.db.models import ConnectorRun
from opti.pipeline import backfill, keyword_hits
from opti.pipeline import connectors as connector_catalog
from opti.pipeline import domain_keywords as dk
from opti.pipeline.backfill import BackfillResult
from opti.pipeline.tasks import run_connector
from opti.sdk.context import EnvSecretProvider

router = APIRouter(tags=["watchlist"])
Reader = Annotated[Principal, Depends(require(Perm.WATCHLIST_READ))]
Editor = Annotated[Principal, Depends(require(Perm.RULES_WRITE))]
Runner = Annotated[Principal, Depends(require(Perm.WATCHLIST_WRITE))]
SAVE_ATTEMPTS = 3
STATS_TIMEOUT = "10s"


def _keyword_error(e: dk.KeywordInvalid) -> HTTPException:
    return HTTPException(404 if e.reason == "not_found" else 422, {"reason": e.reason})


async def _last_runs(request: Request) -> dict[str, BackfillRunOut | None]:
    out: dict[str, BackfillRunOut | None] = {}
    async with get_deps(request).sessions() as s:
        for cid in backfill.BACKFILL_CONNECTORS:
            run = await s.scalar(
                select(ConnectorRun)
                .where(ConnectorRun.connector_id == cid)
                .order_by(ConnectorRun.started_at.desc(), ConnectorRun.id.desc())
                .limit(1)
            )
            out[cid] = None
            if run is not None:
                out[cid] = BackfillRunOut(
                    status=run.status,
                    started_at=run.started_at,
                    ended_at=run.ended_at,
                    items=run.items,
                )
    return out


async def _stats(request: Request, tokens: Sequence[str]) -> dict[str, Any] | None:
    deps = get_deps(request)
    try:
        async with deps.sessions.begin() as s:
            await s.execute(sql_text(f"SET LOCAL statement_timeout = '{STATS_TIMEOUT}'"))
            return dict(await keyword_hits.stats(s, deps.rules.project, tokens, now=deps.clock()))
    except DBAPIError as e:
        if "canceling statement due to statement timeout" in str(e.orig):
            return None
        raise


def _stat(value: str, stats: dict[str, Any] | None) -> KeywordStatOut:
    if stats is None:
        return KeywordStatOut(value=value, findings_30d=None, last_seen=None)
    hit = stats.get(value)
    return KeywordStatOut(
        value=value,
        findings_30d=hit.findings if hit else 0,
        last_seen=hit.last_seen if hit else None,
    )


async def _backfill(request: Request, connector_ids: Sequence[str]) -> dict[str, BackfillOut]:
    if not connector_ids:
        return {}
    deps = get_deps(request)
    if not deps.settings.broker_url:
        results = {
            cid: BackfillResult("unavailable", reason="queue_unconfigured") for cid in connector_ids
        }
    else:

        async def enqueue(cid: str) -> None:
            await run_connector.kiq(cid)

        async with deps.sessions() as s:
            rows = await connector_catalog.catalog(
                s, deps.registry, deps.settings.config_dir, EnvSecretProvider(),
                remote=deps.settings.collector_mode == "remote", now=deps.clock(),
            )  # fmt: skip
            results = await backfill.request(
                s, deps.registry, connector_ids, catalog={r["id"]: r for r in rows},
                enqueue=enqueue, now=deps.clock(),
            )  # fmt: skip
    return {
        cid: BackfillOut(
            status=r.status, reason=r.reason, next_allowed_at=r.next_allowed_at, run_id=r.run_id
        )
        for cid, r in results.items()
    }


async def _change(
    request: Request,
    user: Principal,
    edit: Callable[[ProjectRules], ProjectRules],
    *,
    action: dk.Action,
    kind: dk.KeywordKind,
    value: str,
    affixes: Sequence[str] | None = None,
) -> KeywordChangeOut:
    deps = get_deps(request)
    for attempt in range(SAVE_ATTEMPTS):
        async with deps.sessions() as s:
            current = await revisions.latest(s, "rules")
        version = current.version if current else 0
        text = current.content if current else kinds.read_file("rules", deps.settings)
        try:
            old = kinds.parse("rules", text, allow_aliases=current is None)
        except kinds.ConfigInvalid:
            raise HTTPException(409, {"reason": "rules_invalid"}) from None
        try:
            new = edit(old)
        except dk.KeywordInvalid as e:
            raise _keyword_error(e) from None
        if new == old:
            return KeywordChangeOut(version=version, changed=False, backfill={})
        try:
            changed = await config_store.store(
                request, user, "rules", kinds.from_data("rules", kinds.to_data("rules", new)), new,
                base_version=version, confirm=False, note=dk.describe(action, kind, value),
                restored_from=None,
            )  # fmt: skip
        except HTTPException as e:
            conflict = isinstance(e.detail, dict) and e.detail.get("reason") == "version_conflict"
            if e.status_code == 409 and conflict and attempt + 1 < SAVE_ATTEMPTS:
                continue
            raise
        break
    if not changed:
        return KeywordChangeOut(version=version, changed=False, backfill={})
    detail: dict[str, Any] = {
        "kind": kind, "value": value, "version": version + 1,
    }  # fmt: skip
    if affixes is not None:
        detail["affixes"] = list(affixes)
    async with deps.sessions.begin() as s:
        await record(
            s, request, user, f"watchlist.keyword_{action}", target_type="rules",
            target_id=kind, detail=detail,
        )  # fmt: skip
    return KeywordChangeOut(
        version=version + 1,
        changed=True,
        # 删词不回溯：否则占用最小间隔，挡住紧接着新增的词
        backfill=await _backfill(request, () if action == "removed" else backfill.TRIGGERS[kind]),
    )


@router.get("/watchlist/keywords")
async def list_keywords(request: Request, user: Reader) -> DomainKeywordsOut:
    deps = get_deps(request)
    d = deps.rules.domains
    stats = await _stats(request, [*d.brand_tokens, *d.restricted_tokens, *d.official])
    return DomainKeywordsOut(
        version=deps.config.snapshot.version("rules"),
        short_token_max_len=d.short_token_max_len,
        brand=[_stat(t, stats) for t in d.brand_tokens],
        restricted=[
            RestrictedKeywordOut(**_stat(t, stats).model_dump(), affixes=list(a))
            for t, a in d.restricted_tokens.items()
        ],
        official=[_stat(o, stats) for o in d.official],
        lookalike=list(d.known_lookalikes),
        last_runs=await _last_runs(request),
    )


@router.post("/watchlist/keywords", status_code=201)
async def add_keyword(body: KeywordIn, request: Request, user: Editor) -> KeywordChangeOut:
    try:
        value = dk.normalize(body.kind, body.value)
    except dk.KeywordInvalid as e:
        raise _keyword_error(e) from None
    return await _change(
        request, user, lambda r: dk.add(r, body.kind, body.value, body.affixes),
        action="added", kind=body.kind, value=value,
        affixes=body.affixes if body.kind == "restricted" else None,
    )  # fmt: skip


@router.put("/watchlist/keywords/restricted/{token}")
async def update_affixes(
    token: str, body: AffixesIn, request: Request, user: Editor
) -> KeywordChangeOut:
    value = token.strip().lower()
    return await _change(
        request, user, lambda r: dk.set_affixes(r, value, body.affixes),
        action="updated", kind="restricted", value=value, affixes=body.affixes,
    )  # fmt: skip


@router.delete("/watchlist/keywords/{kind}/{value}")
async def remove_keyword(
    kind: KeywordKindIn, value: str, request: Request, user: Editor
) -> KeywordChangeOut:
    try:
        normalized = dk.normalize(kind, value)
    except dk.KeywordInvalid as e:
        raise _keyword_error(e) from None
    return await _change(
        request, user, lambda r: dk.remove(r, kind, value),
        action="removed", kind=kind, value=normalized,
    )  # fmt: skip


@router.get("/watchlist/keywords/{kind}/{value}/domains")
async def keyword_domains(
    kind: KeywordKindIn,
    value: str,
    request: Request,
    user: Reader,
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> KeywordHitPage:
    if kind == "lookalike":
        raise HTTPException(422, {"reason": "no_hits_for_kind"})
    try:
        token = dk.normalize(kind, value)
    except dk.KeywordInvalid as e:
        raise _keyword_error(e) from None
    deps = get_deps(request)
    async with deps.sessions() as s:
        rows, total = await keyword_hits.hits(
            s, deps.rules.project, token, now=deps.clock(), limit=limit,
            offset=page_offset(page, limit),
        )  # fmt: skip
    return KeywordHitPage(
        items=[KeywordHitOut(**asdict(r)) for r in rows],
        total=total,
    )


@router.post("/watchlist/keywords/backfill", status_code=202)
async def request_backfill(request: Request, user: Runner) -> dict[str, BackfillOut]:
    deps = get_deps(request)
    if not deps.settings.broker_url:
        raise HTTPException(503, "task queue is not configured")
    out = await _backfill(request, backfill.BACKFILL_CONNECTORS)
    async with deps.sessions.begin() as s:
        await record(
            s, request, user, "watchlist.backfill_requested", target_type="rules",
            detail={cid: r.status for cid, r in out.items()},
        )  # fmt: skip
    return out
