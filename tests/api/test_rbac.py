from opti.api.rbac import GRANTS, Perm, Role, permissions


def test_takedown_permissions_follow_separation_of_duties() -> None:
    # 分析员起草、推送工单，但不能审批投诉；处置人员与合规官可以审批（四眼原则另由服务层保证）
    assert {Perm.TAKEDOWN_DRAFT, Perm.TICKETS_PUSH} <= GRANTS[Role.ANALYST]
    assert Perm.TAKEDOWN_APPROVE not in GRANTS[Role.ANALYST]
    assert {Perm.TAKEDOWN_DRAFT, Perm.TAKEDOWN_APPROVE, Perm.EVIDENCE_EXPORT} <= GRANTS[
        Role.RESPONDER
    ]
    assert Perm.TAKEDOWN_APPROVE in GRANTS[Role.COMPLIANCE_OFFICER]
    assert Perm.TAKEDOWN_DRAFT not in GRANTS[Role.COMPLIANCE_OFFICER]
    assert Perm.BLOCKLIST_EXPORT in permissions(["analyst"])
    assert Perm.BLOCKLIST_EXPORT not in permissions(["viewer"])
    assert permissions(["platform_admin"]) == frozenset(
        {
            Perm.USERS_WRITE,
            Perm.ACCESS_WRITE,
            Perm.CERTIFICATES_READ,
            Perm.CERTIFICATES_WRITE,
            Perm.CERTIFICATES_APPROVE,
            Perm.CONNECTORS_READ,
            Perm.CONNECTORS_WRITE,
            Perm.DASHBOARD_DEFAULT,
            Perm.PROJECTS_WRITE,
            Perm.LLM_READ,
            Perm.LLM_ADMIN,
            Perm.CONFIG_READ,
            Perm.CONFIG_WRITE,
            Perm.ORGANIZATION_WRITE,
            Perm.ALERTING_WRITE,
        }
    )
    assert Perm.CONNECTORS_APPROVE in GRANTS[Role.COMPLIANCE_OFFICER]


def test_exposure_accounts_only_for_responders() -> None:
    assert Perm.EXPOSURE_ACCOUNTS in GRANTS[Role.RESPONDER]
    for role in (
        Role.ANALYST,
        Role.VIEWER,
        Role.AUDITOR,
        Role.COMPLIANCE_OFFICER,
        Role.PLATFORM_ADMIN,
    ):
        assert Perm.EXPOSURE_ACCOUNTS not in GRANTS[role]


def test_only_platform_admin_sets_default_dashboard() -> None:
    assert Perm.DASHBOARD_DEFAULT in GRANTS[Role.PLATFORM_ADMIN]
    for role in (
        Role.ANALYST,
        Role.RESPONDER,
        Role.VIEWER,
        Role.AUDITOR,
        Role.COMPLIANCE_OFFICER,
    ):
        assert Perm.DASHBOARD_DEFAULT not in GRANTS[role]


def test_llm_permissions() -> None:
    assert {Perm.LLM_READ, Perm.LLM_ADMIN} <= GRANTS[Role.PLATFORM_ADMIN]
    for role in (Role.AUDITOR, Role.COMPLIANCE_OFFICER):
        assert Perm.LLM_READ in GRANTS[role] and Perm.LLM_ADMIN not in GRANTS[role]
    for role in (Role.ANALYST, Role.RESPONDER, Role.VIEWER):
        assert not {Perm.LLM_READ, Perm.LLM_ADMIN} & GRANTS[role]


def test_config_permissions() -> None:
    for role in Role:
        assert Perm.CONFIG_READ in permissions([role])
    assert Perm.RULES_WRITE in permissions(["analyst"])
    assert Perm.RULES_WRITE not in permissions(["platform_admin"])
    assert Perm.ORGANIZATION_WRITE in permissions(["platform_admin"])
    assert Perm.ORGANIZATION_WRITE not in permissions(["analyst"])
    assert Perm.ALERTING_WRITE == "alerting:write"
    assert Perm.ALERTING_WRITE in permissions(["platform_admin"])
    for role in Role:
        if role not in (Role.PLATFORM_ADMIN, Role.SUPERADMIN):
            assert Perm.ALERTING_WRITE not in permissions([role])


def test_config_write_is_admin_only() -> None:
    assert Perm.CONFIG_WRITE in permissions(["platform_admin"])
    for role in ("analyst", "responder", "viewer", "auditor", "compliance_officer"):
        assert Perm.CONFIG_WRITE not in permissions([role])


def test_alerting_write_is_admin_only() -> None:
    assert Perm.ALERTING_WRITE in permissions(["platform_admin"])
    for role in ("analyst", "responder", "viewer", "auditor", "compliance_officer"):
        assert Perm.ALERTING_WRITE not in permissions([role])


def test_certificate_permissions_do_not_expose_alerts_to_admins() -> None:
    assert {
        Perm.CERTIFICATES_READ,
        Perm.CERTIFICATES_WRITE,
        Perm.CERTIFICATES_APPROVE,
    } <= permissions(["platform_admin"])
    for role in Role:
        if role not in (Role.PLATFORM_ADMIN, Role.SUPERADMIN):
            assert Perm.CERTIFICATES_APPROVE not in GRANTS[role]
    assert Perm.ALERTS_READ not in permissions(["platform_admin"])
    assert Perm.WATCHLIST_READ not in permissions(["platform_admin"])
    assert {Perm.CERTIFICATES_READ, Perm.CERTIFICATES_WRITE} <= permissions(["analyst"])
    for role in ("viewer", "responder"):
        assert Perm.CERTIFICATES_READ in permissions([role])
        assert Perm.CERTIFICATES_WRITE not in permissions([role])
    assert Perm.CERTIFICATES_READ not in permissions(["auditor"])


def test_superadmin_has_all_permissions_and_user_management_is_explicit() -> None:
    assert permissions([Role.SUPERADMIN]) == frozenset(Perm)
    assert {Perm.USERS_WRITE, Perm.ACCESS_WRITE} <= permissions([Role.PLATFORM_ADMIN])
    for role in (Role.ANALYST, Role.RESPONDER, Role.VIEWER, Role.AUDITOR, Role.COMPLIANCE_OFFICER):
        assert not {Perm.USERS_WRITE, Perm.ACCESS_WRITE} & permissions([role])
