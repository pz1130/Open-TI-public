"""Resolve saved authorization on every request; built-in roles remain stable."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.api.rbac import GRANTS, Perm, Role, permissions
from opti.db.models import AccessRole, AppUser, PermissionSet

ROLE_LABELS = {
    "superadmin": "超级管理员",
    "platform_admin": "平台管理员",
    "analyst": "分析员",
    "responder": "处置人员",
    "viewer": "只读用户",
    "auditor": "审计员",
    "compliance_officer": "合规官",
}
PERMISSION_LABELS = {
    "users:write": "管理用户、账号状态、密码和用户授权",
    "access:write": "管理角色及权限集（可授予普通权限）",
    "alerts:read": "查看告警及总览",
    "alerts:triage": "处理、忽略和关闭告警",
    "evidence:read": "查看证据",
    "evidence:export": "导出证据",
    "watchlist:read": "查看监视列表和关键词",
    "watchlist:write": "管理和复查监视域名",
    "certificates:read": "查看证书监控",
    "certificates:write": "管理证书监控任务",
    "certificates:approve": "确认可告警的证书域名",
    "rules:test": "试跑关键词规则",
    "rules:write": "编辑关键词及触发关键词扫描",
    "suppressions:read": "查看抑制规则",
    "suppressions:write": "管理抑制规则",
    "audit:read": "查看审计日志",
    "takedown:read": "查看下架处置",
    "takedown:draft": "起草下架投诉",
    "takedown:approve": "审批下架投诉",
    "tickets:push": "推送工单",
    "blocklist:export": "导出拦截名单",
    "exposure:accounts": "查看泄露账号明细",
    "documents:read": "检索和查看文档",
    "reports:read": "查看报告",
    "stix:export": "导出 STIX 情报",
    "connectors:read": "查看连接器",
    "connectors:write": "配置和运行连接器",
    "connectors:approve": "审批连接器",
    "dashboard:default": "设置默认总览布局",
    "llm:read": "查看模型配置",
    "llm:admin": "管理模型和密钥",
    "config:read": "查看平台配置",
    "config:write": "管理平台、登录和运行配置",
    "projects:write": "切换全平台监测项目",
    "organization:write": "修改机构信息",
    "alerting:write": "管理告警推送",
}


def roles_for(user: AppUser) -> list[str]:
    return sorted(set(user.roles) | set(user.assigned_roles or []))


def builtin_sets() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for perm in Perm:
        group = perm.value.split(":")[0]
        key = f"builtin_{group}"
        if key not in out:
            out[key] = {
                "name": key,
                "display_name": group,
                "description": "内置权限集",
                "permissions": [],
                "builtin": True,
                "version": 0,
            }
        out[key]["permissions"].append(perm.value)
    return out


async def catalog(session: AsyncSession) -> dict[str, Any]:
    sets = builtin_sets()
    for row in await session.scalars(select(PermissionSet).order_by(PermissionSet.name)):
        sets[row.name] = {
            "name": row.name,
            "display_name": row.display_name,
            "description": row.description,
            "permissions": row.permissions,
            "builtin": False,
            "version": row.version,
        }
    roles = [
        {
            "name": role.value,
            "display_name": ROLE_LABELS[role.value],
            "description": "拥有全部当前及未来权限"
            if role == Role.SUPERADMIN
            else "内置角色，权限固定；可创建自定义角色",
            "permission_sets": [],
            "permissions": sorted(p.value for p in grants),
            "builtin": True,
            "version": 0,
        }
        for role, grants in GRANTS.items()
    ]
    for role_row in await session.scalars(select(AccessRole).order_by(AccessRole.name)):
        grants = {
            p
            for name in role_row.permission_sets
            for p in sets.get(name, {}).get("permissions", [])
        }
        roles.append(
            {
                "name": role_row.name,
                "display_name": role_row.display_name,
                "description": role_row.description,
                "permission_sets": role_row.permission_sets,
                "permissions": sorted(grants),
                "builtin": False,
                "version": role_row.version,
            }
        )
    return {
        "permissions": [
            {
                "id": p.value,
                "group": p.value.split(":")[0],
                "description": PERMISSION_LABELS[p.value],
            }
            for p in Perm
        ],
        "roles": roles,
        "permission_sets": list(sets.values()),
    }


async def validate_assignments(
    session: AsyncSession, roles: Iterable[str], sets: Iterable[str]
) -> None:
    known_roles = set(Role) | set(await session.scalars(select(AccessRole.name)))
    known_sets = set(builtin_sets()) | set(await session.scalars(select(PermissionSet.name)))
    if set(roles) - known_roles:
        raise ValueError("包含未知角色")
    if set(sets) - known_sets:
        raise ValueError("包含未知权限集")


async def effective_permissions(session: AsyncSession, user: AppUser) -> frozenset[Perm]:
    roles = roles_for(user)
    if Role.SUPERADMIN in roles:
        return frozenset(Perm)
    grants = set(permissions(roles))
    sets = set(user.permission_sets or [])
    custom_roles = set(roles) - set(Role)
    if custom_roles:
        for linked in await session.scalars(
            select(AccessRole.permission_sets).where(AccessRole.name.in_(custom_roles))
        ):
            sets.update(linked)
    builtins = builtin_sets()
    for name in sets:
        grants.update(Perm(p) for p in builtins.get(name, {}).get("permissions", []))
    custom_sets = sets - set(builtins)
    if custom_sets:
        for saved in await session.scalars(
            select(PermissionSet.permissions).where(PermissionSet.name.in_(custom_sets))
        ):
            grants.update(Perm(p) for p in saved if p in Perm.__members__.values())
    return frozenset(grants)
