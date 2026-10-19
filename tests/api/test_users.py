import asyncio
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from opti.api.bootstrap import BOOTSTRAP_FILE, ensure_superadmin
from opti.api.rbac import Perm, permissions
from opti.db.models import AppUser, AuditLog

pytestmark = pytest.mark.db
PASSWORD = "initial correct horse battery"
NEW_PASSWORD = "changed correct horse battery"
USERS = "/api/v1/admin/users"
ACCESS = "/api/v1/admin/access"


async def root(make_user: Any, login: Any) -> Any:
    await make_user("root", ("superadmin",))
    return await login("root")


async def create(client: Any, **fields: Any) -> Any:
    response = await client.post(
        USERS, json={"username": "bob", "password": PASSWORD, "roles": ["viewer"], **fields}
    )
    assert response.status_code == 201, response.text
    return response.json()


def update_body(account: Any, **fields: Any) -> Any:
    return {
        "display_name": account["display_name"],
        "active": account["active"],
        "roles": account["roles"],
        "permission_sets": account["permission_sets"],
        "base_version": account["version"],
        **fields,
    }


async def test_web_account_password_lifecycle(api: Any, make_user: Any, login: Any) -> None:
    admin = await root(make_user, login)
    bob = await create(admin)
    client = await login("bob", PASSWORD)
    me = (await client.get("/api/v1/auth/me")).json()
    assert me["must_change_password"]
    assert (await client.get("/api/v1/alerts")).json()["detail"][
        "reason"
    ] == "password_change_required"
    for current, new in (("wrong-password", NEW_PASSWORD), (PASSWORD, PASSWORD)):
        assert (
            await client.post(
                "/api/v1/auth/password", json={"current_password": current, "new_password": new}
            )
        ).status_code == 422
    assert (
        await client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        )
    ).status_code == 200
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    client = await login("bob", NEW_PASSWORD)
    assert (await client.get("/api/v1/alerts")).status_code == 200
    current = next(
        row for row in (await admin.get(USERS)).json()["items"] if row["id"] == bob["id"]
    )
    response = await admin.post(
        f"{USERS}/{bob['id']}/password",
        json={"password": PASSWORD, "base_version": current["version"]},
    )
    assert response.status_code == 200 and response.json()["must_change_password"]
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    version = response.json()["version"]
    assert (
        await admin.post(
            f"{USERS}/{bob['id']}/password",
            json={"password": PASSWORD, "base_version": version - 1},
        )
    ).status_code == 409
    async with api.sessions() as s:
        audit = str([a.detail for a in await s.scalars(select(AuditLog))])
        assert PASSWORD not in audit and NEW_PASSWORD not in audit and "password_hash" not in audit
    assert "password_hash" not in json.dumps(bob) and PASSWORD not in json.dumps(bob)


async def test_custom_roles_sets_and_live_permissions(api: Any, make_user: Any, login: Any) -> None:
    admin = await root(make_user, login)
    item = {"name": "monitoring", "display_name": "域名监测", "permissions": ["watchlist:read"]}
    assert (await admin.put(f"{ACCESS}/permission-sets/monitoring", json=item)).status_code == 200
    role = {"name": "domain_team", "display_name": "域名团队", "permission_sets": ["monitoring"]}
    assert (await admin.put(f"{ACCESS}/roles/domain_team", json=role)).status_code == 200
    await make_user("bob", ("domain_team",))
    client = await login("bob")
    assert (await client.get("/api/v1/watchlist")).status_code == 200
    assert (await client.get("/api/v1/alerts")).status_code == 403
    changed = await admin.put(
        f"{ACCESS}/permission-sets/monitoring",
        json={**item, "permissions": ["alerts:read"], "base_version": 1},
    )
    assert changed.status_code == 200, changed.text
    assert (await client.get("/api/v1/watchlist")).status_code == 403
    assert (await client.get("/api/v1/alerts")).status_code == 200
    assert (await admin.put(f"{ACCESS}/permission-sets/monitoring", json=item)).status_code == 409
    assert (
        await admin.delete(f"{ACCESS}/roles/domain_team", params={"base_version": 1})
    ).status_code == 409
    assert (
        await admin.delete(f"{ACCESS}/permission-sets/monitoring", params={"base_version": 2})
    ).status_code == 409
    bob = next(u for u in (await admin.get(USERS)).json()["items"] if u["username"] == "bob")
    changed = await admin.put(
        f"{USERS}/{bob['id']}",
        json=update_body(bob, roles=[], permission_sets=["builtin_watchlist"]),
    )
    assert changed.status_code == 200
    assert (await client.get("/api/v1/watchlist")).status_code == 200
    assert (await client.get("/api/v1/alerts")).status_code == 403
    assert (
        await admin.delete(f"{ACCESS}/roles/domain_team", params={"base_version": 1})
    ).status_code == 200
    assert (
        await admin.delete(f"{ACCESS}/permission-sets/monitoring", params={"base_version": 2})
    ).status_code == 200


async def test_admin_boundaries_and_last_superadmin(api: Any, make_user: Any, login: Any) -> None:
    admin = await root(make_user, login)
    await make_user("platform", ("platform_admin",))
    manager = await login("platform")
    await make_user()
    analyst = await login()
    assert (await analyst.get(USERS)).status_code == 403
    assert (await analyst.get(ACCESS)).status_code == 403
    assert (
        await analyst.post(USERS, json={"username": "evil", "password": PASSWORD})
    ).status_code == 403
    assert (
        await analyst.put(
            f"{ACCESS}/roles/evil",
            json={"name": "evil", "display_name": "evil", "permission_sets": []},
        )
    ).status_code == 403
    root_user = next(u for u in (await admin.get(USERS)).json()["items"] if u["username"] == "root")
    for client, status in ((admin, 409), (manager, 403)):
        assert (
            await client.put(
                f"{USERS}/{root_user['id']}", json=update_body(root_user, active=False)
            )
        ).status_code == status
    assert (
        await manager.post(
            USERS, json={"username": "evil", "password": PASSWORD, "roles": ["superadmin"]}
        )
    ).status_code == 403
    assert (
        await manager.post(
            f"{USERS}/{root_user['id']}/password", json={"password": PASSWORD, "base_version": 1}
        )
    ).status_code == 403
    assert (
        await admin.put(
            f"{ACCESS}/roles/superadmin",
            json={"name": "superadmin", "display_name": "evil", "permission_sets": []},
        )
    ).status_code == 422
    assert (
        await admin.put(
            f"{ACCESS}/permission-sets/builtin_users",
            json={"name": "builtin_users", "display_name": "evil", "permissions": []},
        )
    ).status_code == 422
    assert (
        await admin.put(
            f"{ACCESS}/permission-sets/evil",
            json={"name": "evil", "display_name": "evil", "permissions": ["invented:permission"]},
        )
    ).status_code == 422
    me = (await admin.get("/api/v1/auth/me")).json()
    assert set(me["permissions"]) == set(Perm) == permissions(["superadmin"])


async def test_concurrent_superadmin_removal_keeps_one(
    api: Any, make_user: Any, login: Any
) -> None:
    admin = await root(make_user, login)
    await make_user("root2", ("superadmin",))
    other = await login("root2")
    rows = (await admin.get(USERS)).json()["items"]
    results = await asyncio.gather(
        *(
            client.put(f"{USERS}/{row['id']}", json=update_body(row, active=False))
            for client, row in zip((admin, other), rows, strict=True)
        )
    )
    assert sorted(r.status_code for r in results) in ([200, 409], [200, 403])
    async with api.sessions() as s:
        remaining = [
            u for u in await s.scalars(select(AppUser)) if u.active and "superadmin" in u.roles
        ]
    assert len(remaining) == 1


async def test_locked_superadmin_is_not_a_usable_replacement(
    api: Any, make_user: Any, login: Any
) -> None:
    admin = await root(make_user, login)
    await make_user("lockedroot", ("superadmin",))
    async with api.sessions.begin() as s:
        account = await s.scalar(select(AppUser).where(AppUser.username == "lockedroot"))
        account.locked_until = api.clock() + timedelta(minutes=10)
    account = next(
        row for row in (await admin.get(USERS)).json()["items"] if row["username"] == "root"
    )
    response = await admin.put(f"{USERS}/{account['id']}", json=update_body(account, roles=[]))
    assert response.status_code == 409, response.text


async def test_pagination_unlock_disable_and_sessions(api: Any, make_user: Any, login: Any) -> None:
    admin = await root(make_user, login)
    await make_user("bob", ("viewer",))
    client = await login("bob")
    page = await admin.get(USERS, params={"q": "bob", "page": 1, "limit": 1})
    assert page.json()["total"] == 1 and len(page.json()["items"]) == 1
    bob = page.json()["items"][0]
    response = await admin.delete(
        f"{USERS}/{bob['id']}/sessions", params={"base_version": bob["version"]}
    )
    assert response.status_code == 200
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    bob["version"] += 1
    response = await admin.post(
        f"{USERS}/{bob['id']}/unlock", params={"base_version": bob["version"]}
    )
    assert response.status_code == 200
    bob = response.json()
    response = await admin.put(f"{USERS}/{bob['id']}", json=update_body(bob, active=False))
    assert response.status_code == 200 and not response.json()["active"]
    assert (await admin.put(f"{USERS}/{bob['id']}", json=update_body(bob))).status_code == 409


async def test_password_validation_never_returns_input(
    api: Any, make_user: Any, login: Any
) -> None:
    admin = await root(make_user, login)
    secret = "sensitive"
    response = await admin.post(USERS, json={"username": "bob", "password": secret})
    assert response.status_code == 422 and secret not in response.text
    response = await admin.post(
        "/api/v1/auth/password", json={"current_password": PASSWORD, "new_password": secret}
    )
    assert (
        response.status_code == 422
        and PASSWORD not in response.text
        and secret not in response.text
    )


async def test_bootstrap_is_once_random_and_requires_password_change(
    api: Any, tmp_path: Path, login: Any
) -> None:
    await ensure_superadmin(api.sessions, tmp_path, api.clock())
    credentials = json.loads((tmp_path / BOOTSTRAP_FILE).read_text())
    assert credentials["username"] == "superadmin" and len(credentials["password"]) >= 24
    assert (tmp_path / BOOTSTRAP_FILE).stat().st_mode & 0o777 == 0o600
    await ensure_superadmin(api.sessions, tmp_path, api.clock())
    assert json.loads((tmp_path / BOOTSTRAP_FILE).read_text()) == credentials
    client = await login(credentials["username"], credentials["password"])
    assert (await client.get("/api/v1/auth/me")).json()["must_change_password"]
    from dataclasses import replace

    api.deps.settings = replace(api.deps.settings, state_dir=tmp_path)
    assert (
        await client.post(
            "/api/v1/auth/password",
            json={"current_password": credentials["password"], "new_password": NEW_PASSWORD},
        )
    ).status_code == 200
    assert not (tmp_path / BOOTSTRAP_FILE).exists()
    await ensure_superadmin(api.sessions, tmp_path, api.clock())
    assert not (tmp_path / BOOTSTRAP_FILE).exists()


async def test_bootstrap_does_not_promote_same_named_user(
    api: Any, make_user: Any, tmp_path: Path
) -> None:
    await make_user("superadmin", ("viewer",))
    await asyncio.gather(
        ensure_superadmin(api.sessions, tmp_path, api.clock()),
        ensure_superadmin(api.sessions, tmp_path, api.clock()),
    )
    credentials = json.loads((tmp_path / BOOTSTRAP_FILE).read_text())
    assert credentials["username"] == "superadmin-2"
    async with api.sessions() as s:
        users = list(await s.scalars(select(AppUser).order_by(AppUser.id)))
        assert len(users) == 2 and users[0].roles == ["viewer"] and users[1].roles == ["superadmin"]


async def test_sso_sync_preserves_manual_grants(api: Any, make_user: Any, login: Any) -> None:
    from tests.api.test_oidc_flow import _browser, _login, _setup

    admin = await root(make_user, login)
    idp = _setup(api)
    async with _browser(api) as client:
        assert (await _login(idp, client)).status_code == 303
        account = next(
            row for row in (await admin.get(USERS)).json()["items"] if row["auth_source"] == "oidc"
        )
        response = await admin.put(
            f"{USERS}/{account['id']}",
            json=update_body(account, roles=["auditor"], permission_sets=["builtin_watchlist"]),
        )
        assert response.status_code == 200, response.text
        assert (await _login(idp, client, groups=("opti-responders",))).status_code == 303
        me = (await client.get("/api/v1/auth/me")).json()
        assert me["roles"] == ["auditor", "responder"] and "watchlist:write" in me["permissions"]
        assert (
            await admin.post(
                f"{USERS}/{account['id']}/password",
                json={"password": PASSWORD, "base_version": response.json()["version"] + 1},
            )
        ).status_code == 422
        assert (await _login(idp, client, groups=())).headers["location"] == "/?login_error=no_role"


async def test_only_superadmin_can_change_superadmin_sso_mapping(
    api: Any, make_user: Any, login: Any
) -> None:
    await make_user("platform", ("platform_admin",))
    manager = await login("platform")
    data = (await manager.get("/api/v1/config/identity")).json()["data"]
    data["role_mapping"] = {"superadmin": ["TI-Superadmins"]}
    response = await manager.put("/api/v1/config/identity", json={"data": data, "base_version": 0})
    assert response.status_code == 403, response.text
