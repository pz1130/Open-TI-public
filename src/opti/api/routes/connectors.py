"""Connector catalog and Web-managed instance settings."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from opti.api.deps import Principal, get_deps, record, require
from opti.api.rbac import Perm
from opti.api.schemas import (
    ConnectorApprovalIn,
    ConnectorConfigIn,
    ConnectorConfigOut,
    ConnectorHistoryOut,
    ConnectorOut,
    ConnectorRestoreIn,
    CredentialState,
)
from opti.configs import connector_edits as edits
from opti.configs import kinds
from opti.configs import secrets as config_secrets
from opti.configs.connectors import credential_names
from opti.pipeline import connectors
from opti.sdk.context import EnvSecretProvider
from opti.sdk.manifest import ConnectorManifest, ManifestError, validate_instance_config
from opti.sdk.registry import InstanceConfig

router = APIRouter(tags=["connectors"])
Reader = Annotated[Principal, Depends(require(Perm.CONNECTORS_READ))]
Writer = Annotated[Principal, Depends(require(Perm.CONNECTORS_WRITE))]
Approver = Annotated[Principal, Depends(require(Perm.CONNECTORS_APPROVE))]


def _manifest(request: Request, connector_id: str) -> ConnectorManifest:
    try:
        return get_deps(request).registry.manifest(connector_id)
    except ManifestError:
        raise HTTPException(404, "unknown connector") from None


async def _config(
    request: Request, connector_id: str, saved: edits.Saved | None = None
) -> ConnectorConfigOut:
    deps = get_deps(request)
    manifest = _manifest(request, connector_id)
    snapshot = deps.config.snapshot
    instance = (
        saved.instance
        if saved
        else edits.entry(snapshot.connectors, connector_id, deps.settings.config_dir)
    )
    secrets = EnvSecretProvider()
    plan = manifest.plans.get(instance.plan)
    required = {c.name for c in manifest.credentials if c.required} | set(
        plan.requires if plan else ()
    )
    remote = deps.settings.collector_mode == "remote" and manifest.egress == "overseas"
    async with deps.sessions() as s:
        resolved = await config_secrets.resolve(
            s, edits.KIND, {f"{connector_id}:{c.name}" for c in manifest.credentials},
            deps.keyring, fallback={}, stored_only=True,
        )  # fmt: skip

    def configured(name: str) -> bool | None:
        key = f"{connector_id}:{name}"
        managed, value = key in resolved.values, resolved.values.get(key)
        return (
            bool(value) if managed else (None if remote else bool(secrets.get(connector_id, name)))
        )

    return ConnectorConfigOut(
        id=connector_id,
        darkweb=manifest.darkweb,
        enabled=instance.enabled,
        plan=instance.plan,
        plans=list(manifest.plans),
        config=instance.config,
        config_schema=manifest.config_schema,
        credentials=[
            CredentialState(
                name=c.name,
                required=c.name in required,
                configured=configured(c.name),
                problem=resolved.problems.get(f"{connector_id}:{c.name}"),
            )
            for c in manifest.credentials
        ],
        license_approved=instance.license_approved,
        license_ref=instance.license_ref,
        darkweb_approval_ref=instance.darkweb_approval_ref,
        encryption_key=deps.keyring is not None,
        version=saved.version if saved else snapshot.version(edits.KIND),
        schedule=instance.schedule,
        default_schedule=manifest.schedule.default,
        schedulable=bool(set(manifest.kind) & {"poll", "batch", "generator"}),
    )


async def _save(
    request: Request,
    user: Principal,
    connector_id: str,
    fields: dict[str, Any],
    *,
    action: str,
    detail: dict[str, Any],
    secrets: dict[str, str | None] | None = None,
) -> ConnectorConfigOut:
    """只替换这个连接器的字段，与凭据、审计在同一事务里写入，提交后刷新本进程的配置。"""
    deps = get_deps(request)
    try:
        async with deps.sessions.begin() as s:
            saved = await edits.save_entry(
                s, connector_id, fields, live=deps.config.snapshot.connectors,
                config_dir=deps.settings.config_dir, user=user.username, now=deps.clock(),
            )  # fmt: skip
            if secrets:
                await config_secrets.write(
                    s, edits.KIND, {f"{connector_id}:{name}": v for name, v in secrets.items()},
                    keyring=deps.keyring, user=user.username, now=deps.clock(),
                )  # fmt: skip
                await record(
                    s, request, user, "config.secret_updated", target_type="config",
                    target_id=edits.KIND, detail={"connector": connector_id, "names": sorted(secrets)},
                )  # fmt: skip
            if saved.stored or secrets:
                await record(
                    s, request, user, action, target_type="connector", target_id=connector_id,
                    detail={"version": saved.version, "changed": saved.changed, **detail},
                )  # fmt: skip
    except kinds.ConfigInvalid as e:
        raise HTTPException(422, {"errors": e.errors}) from None
    await deps.config.refresh()
    return await _config(request, connector_id, saved)


@router.get("/connectors")
async def list_connectors(request: Request, user: Reader) -> list[ConnectorOut]:
    deps = get_deps(request)
    async with deps.sessions() as s:
        rows = await connectors.catalog(
            s, deps.registry, deps.settings.config_dir, EnvSecretProvider(),
            remote=deps.settings.collector_mode == "remote", now=deps.clock(),
        )  # fmt: skip
        resolved = await config_secrets.resolve(
            s, edits.KIND, credential_names(), deps.keyring, fallback={}, stored_only=True
        )
        for row in rows:
            for credential in row["credentials"]:
                key = f"{row['id']}:{credential['name']}"
                credential["problem"] = resolved.problems.get(key)
                if credential["problem"]:
                    credential["configured"] = False
    return [ConnectorOut.model_validate(r) for r in rows]


@router.get("/connectors/{connector_id}/config")
async def get_connector_config(
    connector_id: str, request: Request, user: Reader
) -> ConnectorConfigOut:
    return await _config(request, connector_id)


@router.put("/connectors/{connector_id}/config")
async def update_connector_config(
    connector_id: str,
    body: ConnectorConfigIn,
    request: Request,
    user: Writer,
) -> ConnectorConfigOut:
    deps = get_deps(request)
    manifest = _manifest(request, connector_id)
    if body.plan not in manifest.plans:
        raise HTTPException(422, "unknown connector plan")
    names = {c.name for c in manifest.credentials}
    if set(body.secrets) - names:
        raise HTTPException(422, "unknown credential")
    if any(value == "" for value in body.secrets.values()):
        raise HTTPException(422, "credential must be nonempty or null to clear")
    if any(value is not None for value in body.secrets.values()) and deps.keyring is None:
        raise HTTPException(409, "encryption key is not configured (OPTI_ENCRYPTION_KEY)")
    if body.schedule is not None:
        from pydantic import ValidationError

        try:
            InstanceConfig(schedule=body.schedule)
        except ValidationError:
            raise HTTPException(422, "调度须为五段数字 Cron 表达式（UTC）") from None
        if not set(manifest.kind) & {"poll", "batch", "generator"}:
            raise HTTPException(422, "流式连接器与富化器不使用定时调度")
    try:
        config = validate_instance_config(manifest, body.config)
    except ManifestError as e:
        raise HTTPException(422, str(e)) from None
    return await _save(
        request, user, connector_id,
        {"enabled": body.enabled, "plan": body.plan, "config": config,
         **({"schedule": body.schedule} if "schedule" in body.model_fields_set else {})},
        action="connector.config_updated",
        detail={"credentials_changed": sorted(body.secrets)},
        secrets=body.secrets,
    )  # fmt: skip


@router.put("/connectors/{connector_id}/approval")
async def update_connector_approval(
    connector_id: str,
    body: ConnectorApprovalIn,
    request: Request,
    user: Approver,
) -> ConnectorConfigOut:
    manifest = _manifest(request, connector_id)
    if body.license_approved and not (body.license_ref or "").strip():
        raise HTTPException(422, "approval reference is required")
    if body.license_approved and manifest.darkweb and not (body.darkweb_approval_ref or "").strip():
        raise HTTPException(422, "darkweb approval reference is required")
    reference = (body.license_ref or "").strip() or None
    return await _save(
        request, user, connector_id,
        {
            "license_approved": body.license_approved,
            "license_ref": reference,
            "darkweb_approval_ref": (body.darkweb_approval_ref or "").strip() or None,
        },
        action="connector.approval_updated",
        detail={"approved": body.license_approved, "reference": reference},
    )  # fmt: skip


@router.get("/connectors/{connector_id}/history")
async def connector_history(
    connector_id: str, request: Request, user: Reader
) -> list[ConnectorHistoryOut]:
    deps = get_deps(request)
    _manifest(request, connector_id)
    async with deps.sessions() as s:
        rows = await edits.history(s, connector_id, deps.settings.config_dir)
    return [ConnectorHistoryOut(**asdict(row)) for row in rows]


@router.post("/connectors/{connector_id}/restore")
async def restore_connector(
    connector_id: str, body: ConnectorRestoreIn, request: Request, user: Writer
) -> ConnectorConfigOut:
    """把启用、套餐与参数恢复到某一版；法务批准与凭据不从历史恢复。"""
    deps = get_deps(request)
    _manifest(request, connector_id)
    try:
        async with deps.sessions.begin() as s:
            target = await edits.version_entry(
                s, connector_id, body.version, deps.settings.config_dir
            )
            if target is None:
                raise HTTPException(404, "unknown revision")
            saved = await edits.save_entry(
                s, connector_id, {name: getattr(target, name) for name in edits.CONFIG_FIELDS},
                live=deps.config.snapshot.connectors, config_dir=deps.settings.config_dir,
                user=user.username, now=deps.clock(),
                note=f"恢复 v{body.version} 的参数", restored_from=body.version,
            )  # fmt: skip
            if not saved.stored:
                raise HTTPException(409, {"reason": "nothing_to_restore"})
            await record(
                s, request, user, "connector.restored", target_type="connector",
                target_id=connector_id,
                detail={"version": saved.version, "restored_from": body.version, "changed": saved.changed},
            )  # fmt: skip
    except kinds.ConfigInvalid as e:  # 该版参数已不符合当前 manifest
        raise HTTPException(422, {"errors": e.errors}) from None
    await deps.config.refresh()
    return await _config(request, connector_id, saved)
