"""角色与权限（设计文档 16.2）。权限点只在这里映射，接口只检查权限点。"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum


class Role(StrEnum):
    SUPERADMIN = "superadmin"
    PLATFORM_ADMIN = "platform_admin"
    ANALYST = "analyst"
    RESPONDER = "responder"
    VIEWER = "viewer"
    AUDITOR = "auditor"
    COMPLIANCE_OFFICER = "compliance_officer"


class Perm(StrEnum):
    USERS_WRITE = "users:write"
    ACCESS_WRITE = "access:write"
    ALERTS_READ = "alerts:read"
    ALERTS_TRIAGE = "alerts:triage"
    EVIDENCE_READ = "evidence:read"
    WATCHLIST_READ = "watchlist:read"
    WATCHLIST_WRITE = "watchlist:write"
    CERTIFICATES_READ = "certificates:read"
    CERTIFICATES_WRITE = "certificates:write"
    CERTIFICATES_APPROVE = "certificates:approve"
    RULES_TEST = "rules:test"
    SUPPRESSIONS_READ = "suppressions:read"
    SUPPRESSIONS_WRITE = "suppressions:write"
    AUDIT_READ = "audit:read"

    TAKEDOWN_READ = "takedown:read"
    TAKEDOWN_DRAFT = "takedown:draft"
    TAKEDOWN_APPROVE = "takedown:approve"
    TICKETS_PUSH = "tickets:push"
    EVIDENCE_EXPORT = "evidence:export"
    BLOCKLIST_EXPORT = "blocklist:export"
    EXPOSURE_ACCOUNTS = "exposure:accounts"
    DOCUMENTS_READ = "documents:read"
    REPORTS_READ = "reports:read"
    STIX_EXPORT = "stix:export"
    CONNECTORS_READ = "connectors:read"
    CONNECTORS_WRITE = "connectors:write"
    CONNECTORS_APPROVE = "connectors:approve"
    DASHBOARD_DEFAULT = "dashboard:default"
    LLM_READ = "llm:read"
    LLM_ADMIN = "llm:admin"
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    RULES_WRITE = "rules:write"
    PROJECTS_WRITE = "projects:write"
    ORGANIZATION_WRITE = "organization:write"
    ALERTING_WRITE = "alerting:write"


_RESPONSE = frozenset(
    {
        Perm.TAKEDOWN_READ,
        Perm.TAKEDOWN_DRAFT,
        Perm.TICKETS_PUSH,
        Perm.EVIDENCE_EXPORT,
        Perm.BLOCKLIST_EXPORT,
        Perm.STIX_EXPORT,
    }
)

GRANTS: dict[Role, frozenset[Perm]] = {
    Role.SUPERADMIN: frozenset(Perm),
    Role.ANALYST: frozenset(
        {
            Perm.ALERTS_READ,
            Perm.ALERTS_TRIAGE,
            Perm.EVIDENCE_READ,
            Perm.WATCHLIST_READ,
            Perm.CERTIFICATES_READ,
            Perm.WATCHLIST_WRITE,
            Perm.CERTIFICATES_WRITE,
            Perm.RULES_TEST,
            Perm.SUPPRESSIONS_READ,
            Perm.SUPPRESSIONS_WRITE,
            Perm.DOCUMENTS_READ,
            Perm.REPORTS_READ,
            Perm.CONNECTORS_READ,
            Perm.CONFIG_READ,
            Perm.RULES_WRITE,
        }
    )
    | _RESPONSE,
    # 处置人员（设计文档 16.2）：跟踪处置、导出证据包、起草与审批下架投诉（不能审批自己起草的）
    Role.RESPONDER: frozenset(
        {
            Perm.ALERTS_READ,
            Perm.EVIDENCE_READ,
            Perm.WATCHLIST_READ,
            Perm.CERTIFICATES_READ,
            Perm.SUPPRESSIONS_READ,
            Perm.TAKEDOWN_APPROVE,
            Perm.EXPOSURE_ACCOUNTS,
            Perm.DOCUMENTS_READ,
            Perm.REPORTS_READ,
            Perm.CONNECTORS_READ,
            Perm.CONFIG_READ,
        }
    )
    | _RESPONSE,
    Role.VIEWER: frozenset(
        {
            Perm.ALERTS_READ,
            Perm.WATCHLIST_READ,
            Perm.CERTIFICATES_READ,
            Perm.DOCUMENTS_READ,
            Perm.REPORTS_READ,
            Perm.CONFIG_READ,
        }
    ),
    Role.AUDITOR: frozenset({Perm.AUDIT_READ, Perm.LLM_READ, Perm.CONFIG_READ}),
    # 合规官审批以机构名义发出的投诉，但不起草
    Role.COMPLIANCE_OFFICER: frozenset(
        {
            Perm.AUDIT_READ,
            Perm.LLM_READ,
            Perm.RULES_TEST,
            Perm.SUPPRESSIONS_READ,
            Perm.TAKEDOWN_READ,
            Perm.TAKEDOWN_APPROVE,
            Perm.CONNECTORS_READ,
            Perm.CONNECTORS_APPROVE,
            Perm.CONFIG_READ,
        }
    ),
    # 平台管理员可管理普通用户及授权；超管角色只能由超管授予。
    Role.PLATFORM_ADMIN: frozenset(
        {
            Perm.USERS_WRITE,
            Perm.ACCESS_WRITE,
            Perm.CERTIFICATES_APPROVE,
            Perm.CERTIFICATES_READ,
            Perm.CERTIFICATES_WRITE,
            Perm.CONNECTORS_READ,
            Perm.CONNECTORS_WRITE,
            Perm.DASHBOARD_DEFAULT,
            Perm.PROJECTS_WRITE,
            Perm.LLM_READ,
            Perm.LLM_ADMIN,
            Perm.CONFIG_READ,
            Perm.ORGANIZATION_WRITE,
            Perm.CONFIG_WRITE,
            Perm.ALERTING_WRITE,
        }
    ),
}


def permissions(roles: Iterable[str]) -> frozenset[Perm]:
    out: set[Perm] = set()
    for r in roles:
        if r in Role.__members__.values():
            out |= GRANTS[Role(r)]
    return frozenset(out)
