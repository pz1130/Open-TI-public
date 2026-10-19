"""真实身份提供方（Keycloak）上的授权码 + PKCE 全流程：机密客户端、组映射到 ID Token、登出地址。"""

import html
import os
import re
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from opti.api.oidc.client import OidcClient
from opti.api.oidc.config import OidcConfig
from opti.sdk.http import RateLimitedHttpClient

pytestmark = [pytest.mark.db, pytest.mark.keycloak]
IMAGE = "quay.io/keycloak/keycloak:26.0"
PASSWORD = "correct horse battery staple"
REDIRECT = "http://testserver/api/v1/auth/oidc/callback"
CLIENT = {
    "clientId": "opti", "protocol": "openid-connect", "publicClient": False, "secret": "opti-secret",
    "redirectUris": [REDIRECT], "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
    "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "http://testserver/"},
    "protocolMappers": [
        {"name": "groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
         "config": {"claim.name": "groups", "full.path": "false", "id.token.claim": "true",
                    "access.token.claim": "false", "userinfo.token.claim": "false"}},
    ],
}  # fmt: skip
USER = {
    "username": "kc-alice", "enabled": True, "email": "alice@example.org", "emailVerified": True,
    "firstName": "Alice", "lastName": "Analyst", "groups": ["/opti-analysts"],
    "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
}  # fmt: skip


def _setup_realm(base: str) -> None:
    with httpx.Client(base_url=base, timeout=60) as c:
        r = c.post(
            "/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "admin",
                "password": "admin",
            },
        )
        for _ in range(30):
            if r.status_code != 503:
                break
            time.sleep(1)
            r = c.post(
                "/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "admin",
                    "password": "admin",
                },
            )
        assert r.status_code == 200, (base, r.status_code, r.text[:300])
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        for path, body in [
            ("/admin/realms", {"realm": "opti", "enabled": True, "sslRequired": "NONE"}),
            ("/admin/realms/opti/clients", CLIENT),
            ("/admin/realms/opti/groups", {"name": "opti-analysts"}),
            ("/admin/realms/opti/users", USER),
        ]:
            c.post(path, json=body, headers=h).raise_for_status()


@pytest.fixture(scope="module")
def keycloak_url() -> Iterator[str]:
    external = os.environ.get(
        "OPTI_TEST_KEYCLOAK_URL"
    )  # 已在运行、且已按 _setup_realm 配置的 Keycloak
    if external:
        yield external.rstrip("/")
        return
    try:
        from testcontainers.core.container import DockerContainer
        from testcontainers.core.waiting_utils import wait_for_logs

        container = (
            DockerContainer(IMAGE)
            .with_env("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .with_env("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .with_command("start-dev")
            .with_exposed_ports(8080)
        )
        container.start()
        wait_for_logs(container, "Listening on:", timeout=240)
    except Exception as e:  # Docker 不可用时跳过
        pytest.skip(f"无法启动 Keycloak 测试容器：{e}")
    try:
        base = f"http://{'127.0.0.1' if container.get_container_host_ip() == 'localhost' else container.get_container_host_ip()}:{container.get_exposed_port(8080)}"
        _setup_realm(base)
        yield base
    finally:
        container.stop()


async def test_keycloak_login_and_logout(api: Any, keycloak_url: str) -> None:
    issuer = f"{keycloak_url}/realms/opti"
    cfg = OidcConfig(
        enabled=True, issuer=issuer, client_id="opti", allow_insecure_http=True,
        post_logout_redirect_uri="http://testserver/", role_mapping={"analyst": ("opti-analysts",)},
    )  # fmt: skip
    http = RateLimitedHttpClient()
    api.app.state.deps.oidc = OidcClient(cfg, http, "opti-secret", redirect_uri=REDIRECT)
    app = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api.app),
        base_url="http://testserver",
        headers={"X-Requested-With": "opti"},
    )
    idp = httpx.AsyncClient(
        timeout=60, follow_redirects=False
    )  # 扮演浏览器访问 Keycloak（保存其 Cookie）
    try:
        r = await app.get("/api/v1/auth/oidc/start", params={"next": "/watchlist"})
        assert r.status_code == 303 and r.headers["location"].startswith(
            f"{issuer}/protocol/openid-connect/auth?"
        )
        page = await idp.get(r.headers["location"])
        assert page.status_code == 200, page.text[:500]
        m = re.search(r'action="([^"]*login-actions/authenticate[^"]*)"', page.text)
        assert m is not None, "Keycloak 登录表单变了：请更新表单解析"
        # Keycloak sets Secure cookies on its local HTTP dev endpoint; browsers exempt loopback, httpx does not.
        for cookie in idp.cookies.jar:
            cookie.secure = False
        r = await idp.post(
            html.unescape(m.group(1)),
            data={"username": "kc-alice", "password": PASSWORD, "credentialId": ""},
        )
        assert r.status_code == 302, (r.status_code, re.sub(r"<[^>]+>", " ", r.text)[-500:])
        callback = urlsplit(r.headers["location"])
        assert f"{callback.scheme}://{callback.netloc}{callback.path}" == REDIRECT
        r = await app.get(f"/api/v1/auth/oidc/callback?{callback.query}")
        assert r.status_code == 303 and r.headers["location"] == "/watchlist", r.headers.get(
            "location"
        )
        me = (await app.get("/api/v1/auth/me")).json()
        assert (
            me["username"] == "kc-alice"
            and me["roles"] == ["analyst"]
            and me["auth_source"] == "oidc"
        )
        assert me["display_name"] == "Alice Analyst"
        out = (await app.post("/api/v1/auth/logout")).json()
        assert out["logout_url"].startswith(
            f"{issuer}/protocol/openid-connect/logout?client_id=opti"
        )
    finally:
        await app.aclose()
        await idp.aclose()
        await http.aclose()
