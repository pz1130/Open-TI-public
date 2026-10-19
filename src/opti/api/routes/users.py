"""Global Web account management and reusable authorization definitions."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api import access, security
from opti.api.access_schemas import (
    AccessCatalog,
    AccessRoleIn,
    PermissionSetIn,
    UserCreateIn,
    UserOut,
    UserPage,
    UserPasswordIn,
    UserUpdateIn,
)
from opti.api.deps import CurrentUser, Principal, get_deps, record, require
from opti.api.pagination import page_offset
from opti.api.rbac import Perm, Role
from opti.db.models import AccessRole, ApiSession, AppUser, PermissionSet

router = APIRouter(tags=["users"])
Manager = Annotated[Principal, Depends(require(Perm.USERS_WRITE))]
AccessManager = Annotated[Principal, Depends(require(Perm.ACCESS_WRITE))]


async def _lock(s: AsyncSession, user: Principal, permission: Perm) -> None:
    await s.execute(select(func.pg_advisory_xact_lock(func.hashtext("opti:access_management"))))
    actor = await s.get(AppUser, user.user_id, populate_existing=True)
    if (
        actor is None
        or not actor.active
        or permission not in await access.effective_permissions(s, actor)
    ):
        raise HTTPException(403, "管理权限已变化，请刷新页面")
    if set(access.roles_for(actor)) != set(user.roles):
        raise HTTPException(409, "管理角色已变化，请刷新后重试")


async def _account(s: AsyncSession, user_id: int, version: int) -> AppUser:
    user = await s.get(AppUser, user_id, with_for_update=True)
    if user is None:
        raise HTTPException(404, "用户不存在")
    if user.access_version != version:
        raise HTTPException(409, "用户已被修改，请刷新后重试")
    return user


def _protect_superadmin(actor: Principal, roles: list[str]) -> None:
    if Role.SUPERADMIN in roles and Role.SUPERADMIN not in actor.roles:
        raise HTTPException(403, "只有超管可以管理或授予超管角色")


async def _validate(s: AsyncSession, roles: list[str], sets: list[str]) -> None:
    try:
        await access.validate_assignments(s, roles, sets)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


async def _out(s: AsyncSession, user: AppUser) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        auth_source=user.auth_source,
        active=user.active,
        roles=user.roles if user.auth_source == "local" else user.assigned_roles,
        idp_roles=user.roles if user.auth_source == "oidc" else [],
        permission_sets=user.permission_sets,
        permissions=sorted(p.value for p in await access.effective_permissions(s, user)),
        must_change_password=user.must_change_password,
        locked_until=user.locked_until,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        version=user.access_version,
    )


@router.get("/admin/users")
async def list_users(
    request: Request,
    user: Manager,
    q: Annotated[str, Query(max_length=100)] = "",
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> UserPage:
    async with get_deps(request).sessions() as s:
        query = select(AppUser)
        if q.strip():
            query = query.where(
                or_(
                    AppUser.username.icontains(q.strip(), autoescape=True),
                    AppUser.display_name.icontains(q.strip(), autoescape=True),
                )
            )
        total = await s.scalar(select(func.count()).select_from(query.subquery()))
        rows = await s.scalars(
            query.order_by(AppUser.id).offset(page_offset(page, limit)).limit(limit)
        )
        return UserPage(items=[await _out(s, row) for row in rows], total=total or 0)


@router.post("/admin/users", status_code=201)
async def create_user(body: UserCreateIn, request: Request, user: Manager) -> UserOut:
    deps = get_deps(request)
    async with deps.sessions.begin() as s:
        await _lock(s, user, Perm.USERS_WRITE)
        _protect_superadmin(user, body.roles)
        await _validate(s, body.roles, body.permission_sets)
        try:
            account = await security.create_user(
                s,
                username=body.username,
                password=body.password.get_secret_value(),
                roles=body.roles,
                display_name=body.display_name,
                now=deps.clock(),
            )
        except security.UserError as e:
            raise HTTPException(422, str(e)) from None
        account.permission_sets = sorted(set(body.permission_sets))
        account.must_change_password = True
        await record(
            s,
            request,
            user,
            "user.create",
            target_type="app_user",
            target_id=account.username,
            detail={"roles": account.roles, "permission_sets": account.permission_sets},
        )
        return await _out(s, account)


@router.put("/admin/users/{user_id}")
async def update_user(user_id: int, body: UserUpdateIn, request: Request, user: Manager) -> UserOut:
    async with get_deps(request).sessions.begin() as s:
        await _lock(s, user, Perm.USERS_WRITE)
        account = await _account(s, user_id, body.base_version)
        _protect_superadmin(user, [*access.roles_for(account), *body.roles])
        await _validate(s, body.roles, body.permission_sets)
        remains_root = body.active and Role.SUPERADMIN in (
            body.roles if account.auth_source == "local" else [*account.roles, *body.roles]
        )
        if account.active and Role.SUPERADMIN in access.roles_for(account) and not remains_root:
            others = await s.scalars(
                select(AppUser).where(AppUser.id != user_id, AppUser.active.is_(True))
            )
            if not any(
                Role.SUPERADMIN in access.roles_for(other)
                and (account.auth_source != "local" or other.auth_source == "local")
                and (other.locked_until is None or other.locked_until <= get_deps(request).clock())
                for other in others
            ):
                raise HTTPException(409, "不能停用或移除最后一个可用的超管账号")
        account.display_name, account.active = body.display_name, body.active
        if account.auth_source == "local":
            account.roles = sorted(set(body.roles))
        else:
            account.assigned_roles = sorted(set(body.roles))
        account.permission_sets = sorted(set(body.permission_sets))
        account.access_version += 1
        if not body.active:
            await s.execute(delete(ApiSession).where(ApiSession.user_id == user_id))
        await record(
            s,
            request,
            user,
            "user.update",
            target_type="app_user",
            target_id=account.username,
            detail={
                "active": account.active,
                "roles": body.roles,
                "permission_sets": account.permission_sets,
            },
        )
        return await _out(s, account)


@router.post("/admin/users/{user_id}/password")
async def reset_password(
    user_id: int, body: UserPasswordIn, request: Request, user: Manager
) -> UserOut:
    async with get_deps(request).sessions.begin() as s:
        await _lock(s, user, Perm.USERS_WRITE)
        account = await _account(s, user_id, body.base_version)
        _protect_superadmin(user, access.roles_for(account))
        try:
            await security.set_password(s, account.username, body.password.get_secret_value())
        except security.UserError as e:
            raise HTTPException(422, str(e)) from None
        account.must_change_password = True
        await record(
            s,
            request,
            user,
            "user.password_reset",
            target_type="app_user",
            target_id=account.username,
        )
        return await _out(s, account)


@router.post("/admin/users/{user_id}/unlock")
async def unlock_user(
    user_id: int, request: Request, user: Manager, base_version: Annotated[int, Query(ge=1)]
) -> UserOut:
    async with get_deps(request).sessions.begin() as s:
        await _lock(s, user, Perm.USERS_WRITE)
        account = await _account(s, user_id, base_version)
        _protect_superadmin(user, access.roles_for(account))
        account.failed_logins, account.locked_until = 0, None
        account.access_version += 1
        await record(
            s, request, user, "user.unlock", target_type="app_user", target_id=account.username
        )
        return await _out(s, account)


@router.delete("/admin/users/{user_id}/sessions")
async def revoke_sessions(
    user_id: int, request: Request, user: Manager, base_version: Annotated[int, Query(ge=1)]
) -> dict[str, bool]:
    async with get_deps(request).sessions.begin() as s:
        await _lock(s, user, Perm.USERS_WRITE)
        account = await _account(s, user_id, base_version)
        _protect_superadmin(user, access.roles_for(account))
        await s.execute(delete(ApiSession).where(ApiSession.user_id == user_id))
        account.access_version += 1
        await record(
            s,
            request,
            user,
            "user.sessions_revoked",
            target_type="app_user",
            target_id=account.username,
        )
    return {"revoked": True}


@router.get("/admin/access")
async def access_catalog(request: Request, user: CurrentUser) -> AccessCatalog:
    if not {Perm.USERS_WRITE, Perm.ACCESS_WRITE} & user.perms:
        raise HTTPException(403, "只有用户或授权管理员可以查看授权目录")
    async with get_deps(request).sessions() as s:
        return AccessCatalog.model_validate(await access.catalog(s))


@router.put("/admin/access/permission-sets/{name}")
async def save_permission_set(
    name: str, body: PermissionSetIn, request: Request, user: AccessManager
) -> AccessCatalog:
    async with get_deps(request).sessions.begin() as s:
        await _lock(s, user, Perm.ACCESS_WRITE)
        if name != body.name or name.startswith("builtin_"):
            raise HTTPException(422, "权限集标识无效或属于内置权限集")
        if set(body.permissions) - set(Perm):
            raise HTTPException(422, "包含未知权限")
        row = await s.get(PermissionSet, name)
        if (row.version if row else 0) != body.base_version:
            raise HTTPException(409, "权限集已变化，请刷新后重试")
        if row is None:
            row = PermissionSet(name=name, version=0)
            s.add(row)
        row.display_name, row.description = body.display_name, body.description
        row.permissions = sorted(set(body.permissions))
        row.version += 1
        await s.flush()
        await record(
            s,
            request,
            user,
            "access.permission_set_saved",
            target_type="permission_set",
            target_id=name,
            detail={"permissions": row.permissions, "version": row.version},
        )
        return AccessCatalog.model_validate(await access.catalog(s))


@router.put("/admin/access/roles/{name}")
async def save_role(
    name: str, body: AccessRoleIn, request: Request, user: AccessManager
) -> AccessCatalog:
    async with get_deps(request).sessions.begin() as s:
        await _lock(s, user, Perm.ACCESS_WRITE)
        if name != body.name or name in Role.__members__.values() or name.startswith("builtin_"):
            raise HTTPException(422, "角色标识无效或属于内置角色")
        await _validate(s, [], body.permission_sets)
        row = await s.get(AccessRole, name)
        if (row.version if row else 0) != body.base_version:
            raise HTTPException(409, "角色已变化，请刷新后重试")
        if row is None:
            row = AccessRole(name=name, version=0)
            s.add(row)
        row.display_name, row.description = body.display_name, body.description
        row.permission_sets = sorted(set(body.permission_sets))
        row.version += 1
        await s.flush()
        await record(
            s,
            request,
            user,
            "access.role_saved",
            target_type="access_role",
            target_id=name,
            detail={"permission_sets": row.permission_sets, "version": row.version},
        )
        return AccessCatalog.model_validate(await access.catalog(s))


@router.delete("/admin/access/{kind}/{name}")
async def delete_access_item(
    kind: Literal["roles", "permission-sets"],
    name: str,
    request: Request,
    user: AccessManager,
    base_version: Annotated[int, Query(ge=1)],
) -> dict[str, bool]:
    async with get_deps(request).sessions.begin() as s:
        await _lock(s, user, Perm.ACCESS_WRITE)
        row: AccessRole | PermissionSet | None
        if kind == "roles":
            row = await s.get(AccessRole, name)
        else:
            row = await s.get(PermissionSet, name)
        if row is None:
            raise HTTPException(404, "自定义角色或权限集不存在；内置项不能删除")
        if row.version != base_version:
            raise HTTPException(409, "内容已变化，请刷新后重试")
        accounts = await s.scalars(select(AppUser))
        if any(
            name in (access.roles_for(a) if kind == "roles" else a.permission_sets)
            for a in accounts
        ):
            raise HTTPException(409, "仍有用户使用此项，请先解除分配")
        if kind == "permission-sets":
            links = await s.scalars(select(AccessRole.permission_sets))
            if any(name in linked for linked in links):
                raise HTTPException(409, "仍有角色使用此权限集，请先解除引用")
        await s.delete(row)
        await record(s, request, user, "access.deleted", target_type=kind, target_id=name)
    return {"deleted": True}
