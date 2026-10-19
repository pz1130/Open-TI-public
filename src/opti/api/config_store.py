"""配置保存（设计 2026-10-12-web-config-phase1）：版本冲突检查、项目切换确认、审计与密钥写入。

配置路由与监视列表关键词接口（设计 2026-10-15-domain-keywords）共用。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import func, select

from opti.alerting.config import AlertingConfig
from opti.api.deps import ApiDeps, Principal, get_deps, record
from opti.api.oidc.client import CALLBACK_PATH
from opti.api.rbac import Perm
from opti.configs import kinds, projects, revisions
from opti.configs import secrets as config_secrets
from opti.configs.kinds import KindName
from opti.core.config import ProjectRules
from opti.core.secretbox import Keyring
from opti.db.models import Alert


def _secret_changes(
    kind: str, model: Any, secrets: Mapping[str, str | None] | None, keyring: Keyring | None
) -> dict[str, str | None]:
    if not secrets:
        return {}
    names = kinds.kind(kind).secret_names
    if names is None:
        raise HTTPException(
            422, {"errors": [{"path": "secrets", "message": "该配置没有密钥", "line": None}]}
        )
    allowed = names(model)
    errors = [
        {"path": f"secrets.{name}", "message": "未知的密钥", "line": None}
        for name in sorted(set(secrets) - allowed)
    ]
    for name, value in secrets.items():
        if value is None:
            continue
        if not value.strip() or any(ord(ch) < 32 for ch in value):
            errors.append(
                {"path": f"secrets.{name}", "message": "密钥不能为空或含控制字符", "line": None}
            )
        elif (name == "webhook_url" or name.endswith(":webhook_url")) and not value.startswith(
            "https://"
        ):
            errors.append(
                {"path": f"secrets.{name}", "message": "Webhook 地址必须是 https", "line": None}
            )
    if errors:
        raise HTTPException(422, {"errors": errors})
    if keyring is None and any(value is not None for value in secrets.values()):
        raise HTTPException(409, {"reason": "encryption_key_missing"})
    return dict(secrets)


def _check_oidc(deps: ApiDeps, old: Any, new: Any, confirm: bool) -> None:
    if not isinstance(new, AlertingConfig) or not isinstance(old, AlertingConfig):
        return
    if (
        deps.oidc is None
        or deps.oidc.cfg.redirect_uri
        or old.public_base_url == new.public_base_url
    ):
        return
    if not confirm:
        raise HTTPException(
            409,
            {
                "reason": "oidc_redirect_change",
                "redirect_uri": f"{new.public_base_url}{CALLBACK_PATH}",
            },
        )


async def store(
    request: Request,
    user: Principal,
    kind: KindName,
    text: str,
    model: Any,
    *,
    base_version: int,
    confirm: bool,
    note: str | None,
    restored_from: int | None,
    confirm_oidc: bool = False,
    secrets: Mapping[str, str | None] | None = None,
) -> bool:
    deps = get_deps(request)
    changes = _secret_changes(kind, model, secrets, deps.keyring)
    stored = False
    async with deps.sessions.begin() as s:
        if kind == "rules":
            await s.execute(
                select(func.pg_advisory_xact_lock(func.hashtext("config_revision:rules")))
            )
        current = await revisions.latest(s, kind)
        version = current.version if current else 0
        if base_version != version:
            raise HTTPException(
                409,
                {
                    "reason": "version_conflict",
                    "current_version": version,
                    "updated_by": current.created_by if current else None,
                },
            )
        current_text = current.content if current else kinds.read_file(kind, deps.settings)
        content_changed = kinds.digest_of(text) != kinds.digest_of(current_text)
        if not content_changed and not changes:
            return False
        if kind == "identity" and "superadmin" not in user.roles:
            current_identity = deps.config.snapshot.identity
            if model.role_mapping.get("superadmin") or current_identity.role_mapping.get(
                "superadmin"
            ):
                raise HTTPException(403, "涉及超管角色映射的单点登录配置只能由超管修改")
        old: Any = None
        old_project: str | None = None
        if content_changed:
            if isinstance(model, ProjectRules):
                # 损坏的规则头无法解析时，沿用已生效的项目标识。
                try:
                    old = kinds.parse(kind, current_text, allow_aliases=current is None)
                except kinds.ConfigInvalid:
                    if current is None:
                        raise
                    old_project = deps.config.snapshot.rules.project
                else:
                    assert isinstance(old, ProjectRules)
                    old_project = old.project
                if model.project != old_project and Perm.PROJECTS_WRITE not in user.perms:
                    raise HTTPException(403, "只有平台管理员可以切换监测项目")
                if model.project != old_project and not confirm:
                    count = await s.scalar(
                        select(func.count())
                        .select_from(Alert)
                        .where(Alert.project_id == old_project)
                    )
                    raise HTTPException(
                        409,
                        {
                            "reason": "project_change",
                            "from": old_project,
                            "to": model.project,
                            "alert_count": int(count or 0),
                        },
                    )
            elif isinstance(model, AlertingConfig):
                try:
                    old = kinds.parse(kind, current_text, allow_aliases=current is None)
                except kinds.ConfigInvalid:
                    if current is None:
                        raise
                    # 损坏的告警头无法解析时，用已生效的平台地址判断回调是否变化。
                    old = deps.config.snapshot.alerting
            _check_oidc(deps, old, model, confirm_oidc)
            if isinstance(model, ProjectRules):
                await projects.save(s, old if isinstance(old, ProjectRules) else deps.rules)
                await projects.save(s, model)
            try:
                row = await revisions.append(
                    s,
                    kind,
                    text,
                    base_version=base_version,
                    user=user.username,
                    note=note,
                    now=deps.clock(),
                    restored_from=restored_from,
                )
            except revisions.VersionConflict as e:
                raise HTTPException(
                    409,
                    {
                        "reason": "version_conflict",
                        "current_version": e.current,
                        "updated_by": None,
                    },
                ) from None
            detail: dict[str, Any] = {"kind": kind, "version": row.version, "digest": row.digest}
            if restored_from is not None:
                detail["restored_from"] = restored_from
            action = "config.restored" if restored_from is not None else "config.saved"
            await record(
                s, request, user, action, target_type="config", target_id=kind, detail=detail
            )
            if old_project is not None and model.project != old_project:
                await record(
                    s,
                    request,
                    user,
                    "config.project_changed",
                    target_type="config",
                    target_id=kind,
                    detail={"from": old_project, "to": model.project, "version": row.version},
                )
        names = kinds.kind(kind).secret_names
        if names is not None:
            if changes:
                await config_secrets.write(
                    s, kind, changes, keyring=deps.keyring, user=user.username, now=deps.clock()
                )
            deleted = await config_secrets.prune(s, kind, names(model))
            if changes or deleted:
                await record(
                    s,
                    request,
                    user,
                    "config.secret_updated",
                    target_type="config",
                    target_id=kind,
                    detail={
                        "kind": kind,
                        "replaced": sorted(
                            name for name, value in changes.items() if value is not None
                        ),
                        "cleared": sorted(name for name, value in changes.items() if value is None),
                        "deleted": deleted,
                    },
                )
        stored = True
    if stored:
        await deps.config.refresh()
    return content_changed
