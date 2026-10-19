"""大模型研判配置（设计 2026-10-10-llm-providers）：供应商、密钥（只写不读）、主备与运行参数。"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.deps import ApiDeps, Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import (
    LlmModelsOut,
    LlmPresetOut,
    LlmProviderIn,
    LlmProviderOut,
    LlmProviderPatch,
    LlmSettingsIn,
    LlmSettingsOut,
    LlmStatusOut,
    LlmTestOut,
)
from opti.core.adjudication import AdjudicationError
from opti.core.secretbox import Keyring
from opti.db.models import Adjudication, LlmProvider, LlmSettings
from opti.llm import open_provider
from opti.llm_presets import (
    BY_KEY,
    PRESETS,
    Preset,
    check_base_url,
    check_proxy,
    provider_base_url,
    proxy_hint,
)
from opti.pipeline import llm_runtime

router = APIRouter(tags=["llm"])
Reader = Annotated[Principal, Depends(require(Perm.LLM_READ))]
Admin = Annotated[Principal, Depends(require(Perm.LLM_ADMIN))]
SETTINGS_FIELDS = ("enabled", "primary_id", "backup_id", "gray_zone_low", "gray_zone_high",
                   "max_per_run", "max_attempts", "max_wait_minutes", "summary_language",
                   "code_enabled")  # fmt: skip
PLAIN_FIELDS = ("name", "base_url", "model", "json_mode", "temperature", "timeout_seconds")


def _hint(secret: str) -> str | None:
    return secret[-4:] if len(secret) >= 8 else None


def _keyring(deps: ApiDeps) -> Keyring:
    if deps.keyring is None:
        raise HTTPException(
            409,
            "尚未初始化凭据加密主密钥，请由管理员前往「配置 → 管理员 → 凭据加密主密钥」完成初始化",
        )
    return deps.keyring


def _preset(key: str) -> Preset:
    preset = BY_KEY.get(key)
    if preset is None:
        raise HTTPException(422, "unknown preset")
    return preset


def _checked(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


async def _settings(s: AsyncSession, *, lock: bool = False) -> LlmSettings | None:
    return await s.get(LlmSettings, llm_runtime.SETTINGS_ID, with_for_update=lock)


def _settings_values(row: LlmSettings | None) -> dict[str, Any]:
    if row is None:
        cfg = llm_runtime.settings_cfg(None)
        return {"enabled": False, "primary_id": None, "backup_id": None,
                "gray_zone_low": cfg.gray_zone[0], "gray_zone_high": cfg.gray_zone[1],
                "max_per_run": cfg.max_per_run, "max_attempts": cfg.max_attempts,
                "max_wait_minutes": cfg.max_wait_minutes, "summary_language": cfg.summary_language,
                "code_enabled": cfg.code_enabled}  # fmt: skip
    return {f: getattr(row, f) for f in SETTINGS_FIELDS}


def _in_use(row: LlmProvider, settings: LlmSettings | None) -> str | None:
    if settings is not None and settings.primary_id == row.id:
        return "primary"
    if settings is not None and settings.backup_id == row.id:
        return "backup"
    return None


def _out(row: LlmProvider, settings: LlmSettings | None) -> LlmProviderOut:
    preset = BY_KEY.get(row.preset)
    return LlmProviderOut(
        id=row.id, name=row.name, preset=row.preset,
        group=preset.group if preset is not None else "local", base_url=provider_base_url(row.preset, row.base_url),
        model=row.model, api_key_set=row.api_key_enc is not None, api_key_hint=row.api_key_hint,
        proxy_hint=row.proxy_hint, json_mode=row.json_mode, temperature=row.temperature,
        timeout_seconds=row.timeout_seconds, last_test_at=row.last_test_at,
        last_test_ok=row.last_test_ok, last_test_error=row.last_test_error,
        in_use=_in_use(row, settings),  # type: ignore[arg-type]
        updated_at=row.updated_at,
    )  # fmt: skip


async def _set_secret(
    s: AsyncSession, request: Request, user: Principal, row: LlmProvider, field: str,
    value: str | None, keyring: Keyring | None,
) -> None:  # fmt: skip
    """写入或清除 api_key / proxy 的密文与提示，并记审计（detail 只有提示）。"""
    action = "key" if field == "api_key" else "proxy"
    if value is None:
        setattr(row, f"{field}_enc", None)
        setattr(row, f"{field}_hint", None)
        await record(s, request, user, f"llm.provider.{action}_clear",
                     target_type="llm_provider", target_id=row.id)  # fmt: skip
        return
    assert keyring is not None
    hint = _hint(value) if field == "api_key" else proxy_hint(value)
    setattr(row, f"{field}_enc", keyring.encrypt(value, aad=llm_runtime.aad(row.id, field)))
    setattr(row, f"{field}_hint", hint)
    await record(s, request, user, f"llm.provider.{action}_set", target_type="llm_provider",
                 target_id=row.id, detail={"hint": hint})  # fmt: skip


@router.get("/llm/presets")
async def list_presets(user: Reader) -> list[LlmPresetOut]:
    return [LlmPresetOut.model_validate(p.public()) for p in PRESETS]


@router.get("/llm/status")
async def get_status(request: Request, user: Reader) -> LlmStatusOut:
    deps = get_deps(request)
    since = deps.clock() - timedelta(hours=24)

    def count(*where: Any) -> Any:
        return select(func.count()).select_from(Adjudication).where(*where)

    async with deps.sessions() as s:
        rt = await llm_runtime.load(s, deps.keyring)
        settings = await _settings(s)
        queue = await s.scalar(count(Adjudication.status == "pending")) or 0
        done = (
            await s.scalar(count(Adjudication.status == "done", Adjudication.updated_at >= since))
            or 0
        )
        failed = (
            await s.scalar(count(Adjudication.status == "failed", Adjudication.updated_at >= since))
            or 0
        )
    return LlmStatusOut(
        encryption_key=deps.keyring is not None, problem=rt.problem, queue=queue,
        done_24h=done, failed_24h=failed,
        worker_problem=settings.worker_problem if settings else None,
        worker_checked_at=settings.worker_checked_at if settings else None,
    )  # fmt: skip


@router.get("/llm/settings")
async def get_settings(request: Request, user: Reader) -> LlmSettingsOut:
    async with get_deps(request).sessions() as s:
        row = await _settings(s)
    return LlmSettingsOut(**_settings_values(row), updated_at=row.updated_at if row else None)


@router.put("/llm/settings")
async def put_settings(request: Request, user: Admin, body: LlmSettingsIn) -> LlmSettingsOut:
    deps = get_deps(request)
    now = deps.clock()
    async with deps.sessions.begin() as s:
        for pid in (body.primary_id, body.backup_id):
            if pid is None:
                continue
            provider = await s.get(LlmProvider, pid)
            if provider is None:
                raise HTTPException(422, "provider not found")
            preset = BY_KEY.get(provider.preset)
            if preset is not None and preset.key_required and provider.api_key_enc is None:
                raise HTTPException(422, "provider has no API key")
        before = _settings_values(await _settings(s, lock=True))
        after = body.model_dump()
        values = {**after, "updated_at": now, "updated_by": user.user_id}
        await s.execute(
            insert(LlmSettings)
            .values(id=llm_runtime.SETTINGS_ID, **values)
            .on_conflict_do_update(index_elements=["id"], set_=values)
        )
        changes = {k: [before[k], after[k]] for k in SETTINGS_FIELDS if before[k] != after[k]}
        await record(s, request, user, "llm.settings.update", target_type="llm_settings",
                     detail={"changes": changes})  # fmt: skip
    return LlmSettingsOut(**after, updated_at=now)


@router.get("/llm/providers")
async def list_providers(request: Request, user: Reader) -> list[LlmProviderOut]:
    async with get_deps(request).sessions() as s:
        settings = await _settings(s)
        rows = (await s.scalars(select(LlmProvider).order_by(LlmProvider.name))).all()
    return [_out(r, settings) for r in rows]


@router.post("/llm/providers", status_code=201)
async def create_provider(request: Request, user: Admin, body: LlmProviderIn) -> LlmProviderOut:
    deps = get_deps(request)
    preset = _preset(body.preset)
    base_url = _checked(check_base_url, preset, body.base_url)
    proxy = _checked(check_proxy, body.proxy) if body.proxy else None
    keyring = _keyring(deps) if body.api_key or proxy else deps.keyring
    now = deps.clock()
    async with deps.sessions.begin() as s:
        row = LlmProvider(
            name=body.name, preset=preset.key, base_url=base_url, model=body.model,
            json_mode=body.json_mode, temperature=body.temperature,
            timeout_seconds=body.timeout_seconds, created_at=now, updated_at=now,
            updated_by=user.user_id,
        )  # fmt: skip
        s.add(row)
        try:
            await s.flush()
        except IntegrityError:
            raise HTTPException(409, "a provider with this name already exists") from None
        await record(s, request, user, "llm.provider.create", target_type="llm_provider",
                     target_id=row.id, detail={"name": row.name, "preset": row.preset,
                                                "base_url": row.base_url, "model": row.model})  # fmt: skip
        if body.api_key:
            await _set_secret(s, request, user, row, "api_key", body.api_key, keyring)
        if proxy:
            await _set_secret(s, request, user, row, "proxy", proxy, keyring)
        return _out(row, await _settings(s))


@router.patch("/llm/providers/{provider_id}")
async def update_provider(
    request: Request, user: Admin, provider_id: int, body: LlmProviderPatch
) -> LlmProviderOut:
    deps = get_deps(request)
    fields = body.model_fields_set
    async with deps.sessions.begin() as s:
        row = await s.get(LlmProvider, provider_id, with_for_update=True)
        if row is None:
            raise HTTPException(404, "provider not found")
        preset = _preset(row.preset)
        new: dict[str, Any] = {f: getattr(body, f) for f in PLAIN_FIELDS if f in fields}
        if "base_url" in new:
            new["base_url"] = _checked(check_base_url, preset, new["base_url"])
        proxy = _checked(check_proxy, body.proxy) if "proxy" in fields and body.proxy else None
        if (body.api_key and "api_key" in fields) or proxy:
            _keyring(deps)
        settings = await _settings(s)
        clears_key = "api_key" in fields and body.api_key is None
        if clears_key and preset.key_required and _in_use(row, settings) is not None:
            raise HTTPException(422, "a provider in use requires an API key")
        changes = {k: [getattr(row, k), v] for k, v in new.items() if getattr(row, k) != v}
        for k, (_, v) in changes.items():
            setattr(row, k, v)
        row.updated_at, row.updated_by = deps.clock(), user.user_id
        try:
            await s.flush()
        except IntegrityError:
            raise HTTPException(409, "a provider with this name already exists") from None
        if changes:
            await record(s, request, user, "llm.provider.update", target_type="llm_provider",
                         target_id=row.id, detail={"changes": changes})  # fmt: skip
        if "api_key" in fields:
            await _set_secret(s, request, user, row, "api_key", body.api_key, deps.keyring)
        if "proxy" in fields:
            await _set_secret(s, request, user, row, "proxy", proxy, deps.keyring)
        return _out(row, settings)


@router.delete("/llm/providers/{provider_id}", status_code=204)
async def delete_provider(request: Request, user: Admin, provider_id: int) -> Response:
    async with get_deps(request).sessions.begin() as s:
        row = await s.get(LlmProvider, provider_id, with_for_update=True)
        if row is None:
            raise HTTPException(404, "provider not found")
        if _in_use(row, await _settings(s, lock=True)) is not None:
            raise HTTPException(409, "provider is in use as primary or backup")
        await s.delete(row)
        await record(s, request, user, "llm.provider.delete", target_type="llm_provider",
                     target_id=provider_id, detail={"name": row.name})  # fmt: skip
    return Response(status_code=204)


async def _load_spec(deps: ApiDeps, provider_id: int) -> tuple[LlmProvider, Preset, str]:
    async with deps.sessions() as s:
        row = await s.get(LlmProvider, provider_id)
        if row is None:
            raise HTTPException(404, "provider not found")
        language = llm_runtime.settings_cfg(await _settings(s)).summary_language
    return row, _preset(row.preset), language


@router.post("/llm/providers/{provider_id}/models")
async def list_models(request: Request, user: Admin, provider_id: int) -> LlmModelsOut:
    deps = get_deps(request)
    row, preset, _ = await _load_spec(deps, provider_id)
    if preset.list_models == "no":
        raise HTTPException(409, "this provider does not support listing models")
    try:
        spec = llm_runtime.spec_for(row, deps.keyring)
    except llm_runtime.Unavailable as e:
        raise HTTPException(409, str(e)) from None
    models: list[str] = []
    error: str | None = None
    async with open_provider(spec, transport=deps.llm_transport) as p:
        try:
            models = await p.list_models()
        except AdjudicationError as e:
            error = str(e)
    async with deps.sessions.begin() as s:
        await record(s, request, user, "llm.provider.models", target_type="llm_provider",
                     target_id=provider_id, detail={"ok": error is None, "count": len(models)})  # fmt: skip
    if error is not None:
        raise HTTPException(502, error)
    return LlmModelsOut(models=models)


@router.post("/llm/providers/{provider_id}/test")
async def test_provider(request: Request, user: Admin, provider_id: int) -> LlmTestOut:
    deps = get_deps(request)
    row, _, language = await _load_spec(deps, provider_id)
    started = time.monotonic()
    verdict: str | None = None
    confidence: float | None = None
    error: str | None = None
    try:
        spec = llm_runtime.spec_for(row, deps.keyring)
        async with open_provider(
            spec, summary_language=language, transport=deps.llm_transport
        ) as p:
            result = await p.assess(llm_runtime.sample_input(deps.rules, deps.organization))
        verdict, confidence = result.verdict, result.confidence
    except (llm_runtime.Unavailable, AdjudicationError) as e:
        error = str(e)[:300]
    latency = int((time.monotonic() - started) * 1000)
    now: datetime = deps.clock()
    async with deps.sessions.begin() as s:
        current = await s.get(LlmProvider, provider_id, with_for_update=True)
        if current is not None:
            current.last_test_at, current.last_test_ok, current.last_test_error = (
                now,
                error is None,
                error,
            )
        await record(s, request, user, "llm.provider.test", target_type="llm_provider",
                     target_id=provider_id,
                     detail={"ok": error is None, "latency_ms": latency, "error": error})  # fmt: skip
    return LlmTestOut(ok=error is None, provider=row.name, model=row.model, verdict=verdict,
                      confidence=confidence, latency_ms=latency, error=error)  # fmt: skip
