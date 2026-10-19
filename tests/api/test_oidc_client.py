from urllib.parse import parse_qs, urlsplit

import pytest

from opti.api.oidc.client import OidcClient, OidcError, build_oidc_client, pkce_pair, s256
from opti.api.oidc.config import OidcConfig
from opti.api.oidc.testing import FakeIdp
from opti.sdk.context import EnvSecretProvider
from opti.sdk.testing import make_http

TENANT = "00000000-0000-4000-8000-000000000001"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _client(idp: FakeIdp, clock: Clock | None = None, **cfg: object) -> OidcClient:
    config = OidcConfig.model_validate(
        {"enabled": True, "issuer": idp.issuer, "client_id": idp.client_id,
         "role_mapping": {"analyst": ["opti-analysts"]}, **cfg}
    )  # fmt: skip
    return OidcClient(
        config, make_http(idp.handler), "secret-1",
        redirect_uri="https://ti.example/api/v1/auth/oidc/callback", clock=clock or Clock(),
    )  # fmt: skip


def test_pkce_pair() -> None:
    verifier, challenge = pkce_pair()
    assert 43 <= len(verifier) <= 128 and challenge == s256(verifier) and "=" not in challenge


async def test_full_exchange_and_identity() -> None:
    idp = FakeIdp()
    client = _client(idp)
    p = await client.provider()
    verifier, challenge = pkce_pair()
    url = client.authorize_url(p, state="st", nonce="n-1", challenge=challenge)
    q = parse_qs(urlsplit(url).query)
    assert url.startswith(p.authorization_endpoint + "?")
    assert q["response_type"] == ["code"] and q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == [challenge] and q["state"] == ["st"] and q["nonce"] == ["n-1"]
    assert q["redirect_uri"] == ["https://ti.example/api/v1/auth/oidc/callback"]
    assert q["scope"] == ["openid profile email"]

    idp.issue(
        "c1",
        challenge=challenge,
        nonce="n-1",
        sub="u-7",
        username="Alice@Example.org",
        groups=("opti-analysts",),
    )
    token = await client.exchange(p, "c1", verifier)
    assert idp.token_requests[0]["client_secret"] == "secret-1"
    assert idp.token_requests[0]["code_verifier"] == verifier
    ident = client.identity(await client.validate(p, token, "n-1"))
    assert (ident.subject, ident.username, ident.email) == (
        "u-7",
        "alice@example.org",
        "u-7@example.org",
    )
    assert ident.claim_values == ("opti-analysts",) and ident.issuer == idp.issuer
    assert client.logout_url(p) == f"{idp.issuer}/protocol/openid-connect/logout?client_id=opti"


async def test_wrong_verifier_and_reused_code() -> None:
    idp = FakeIdp()
    client = _client(idp)
    p = await client.provider()
    _, challenge = pkce_pair()
    idp.issue("c1", challenge=challenge, nonce="n")
    with pytest.raises(OidcError) as e:
        await client.exchange(p, "c1", "not-the-verifier-" * 4)
    assert e.value.code == "token"
    with pytest.raises(OidcError):
        await client.exchange(p, "never-issued", "x" * 50)


async def test_discovery_must_match_issuer_and_use_https() -> None:
    idp = FakeIdp()
    idp.discovery_overrides = {"issuer": "https://evil.example/realms/opti"}
    with pytest.raises(OidcError) as e:
        await _client(idp).provider()
    assert e.value.code == "unavailable"
    idp = FakeIdp()
    idp.discovery_overrides = {"token_endpoint": "http://idp.example/token"}
    with pytest.raises(OidcError):
        await _client(idp).provider()
    idp = FakeIdp()
    idp.discovery_overrides = {"jwks_uri": "https://"}
    with pytest.raises(OidcError):
        await _client(idp).provider()
    idp = FakeIdp()
    idp.discovery_overrides = {"jwks_uri": "https://[invalid"}
    with pytest.raises(OidcError):
        await _client(idp).provider()


async def test_malformed_jwks_and_empty_subject_are_rejected() -> None:
    idp = FakeIdp()
    idp.jwks = lambda: ["not-a-key-set"]  # type: ignore[method-assign]
    client = _client(idp)
    p = await client.provider()
    with pytest.raises(OidcError) as error:
        await client.validate(p, idp.id_token(nonce="n"), "n")
    assert error.value.code == "unavailable"

    idp = FakeIdp()
    client = _client(idp)
    p = await client.provider()
    token = idp.id_token(nonce="n", sub="", username="valid")
    with pytest.raises(OidcError) as error:
        await client.validate(p, token, "n")
    assert error.value.code == "id_token"


@pytest.mark.parametrize(
    "kw",
    [
        {"aud": "someone-else"},
        {"aud": ["opti", "other"]},  # 多个受众且没有 azp
        {"iss": "https://other.example/realms/opti"},
        {"exp_delta": -600},  # 已过期（超出 120 秒偏差）
        {"alg": "HS256"},
        {"alg": "none"},
        {"nonce": "different"},
    ],
)
async def test_rejects_bad_tokens(kw: dict[str, object]) -> None:
    idp = FakeIdp()
    client = _client(idp)
    p = await client.provider()
    token = idp.id_token(**{"nonce": "n-1", **kw})  # type: ignore[arg-type]
    with pytest.raises(OidcError) as e:
        await client.validate(p, token, "n-1")
    assert e.value.code == "id_token"


async def test_multiple_audiences_with_azp_ok() -> None:
    idp = FakeIdp()
    client = _client(idp)
    p = await client.provider()
    token = idp.id_token(nonce="n", aud=["opti", "other"], extra={"azp": "opti"})
    assert (await client.validate(p, token, "n"))["sub"] == "u-1"


async def test_key_rotation() -> None:
    idp = FakeIdp()
    clock = Clock()
    client = _client(idp, clock)
    p = await client.provider()
    await client.validate(p, idp.id_token(nonce="n"), "n")
    assert idp.jwks_fetches == 1
    idp.rotate("k2")
    with pytest.raises(OidcError):  # 5 分钟内不为未知密钥反复拉取 JWKS
        await client.validate(p, idp.id_token(nonce="n"), "n")
    assert idp.jwks_fetches == 1
    clock.t += 301
    await client.validate(p, idp.id_token(nonce="n"), "n")
    assert idp.jwks_fetches == 2


async def test_entra_tenant_and_group_overage() -> None:
    issuer = f"https://login.microsoftonline.com/{TENANT}/v2.0"
    idp = FakeIdp(issuer=issuer, client_id="app-1")
    config = OidcConfig.model_validate(
        {"enabled": True, "provider": "entra", "tenant_id": TENANT, "client_id": "app-1",
         "roles_claim": "roles", "role_mapping": {"analyst": ["Opti.Analyst"]}}
    )  # fmt: skip
    client = OidcClient(config, make_http(idp.handler), None, redirect_uri="https://ti.example/cb")
    p = await client.provider()
    ok = await client.validate(
        p, idp.id_token(nonce="n", extra={"tid": TENANT, "roles": ["Opti.Analyst"]}), "n"
    )
    assert client.identity(ok).claim_values == ("Opti.Analyst",)
    with pytest.raises(OidcError) as e:
        await client.validate(p, idp.id_token(nonce="n", extra={"tid": "another-tenant"}), "n")
    assert e.value.code == "id_token"
    overage = await client.validate(
        p, idp.id_token(nonce="n", extra={"tid": TENANT, "_claim_names": {"roles": "src1"}}), "n"
    )
    with pytest.raises(OidcError) as e:
        client.identity(overage)
    assert e.value.code == "too_many_groups"


async def test_unusable_username() -> None:
    idp = FakeIdp()
    client = _client(idp)
    p = await client.provider()
    claims = await client.validate(p, idp.id_token(nonce="n", username="bad name<script>"), "n")
    with pytest.raises(OidcError) as e:
        client.identity(claims)
    assert e.value.code == "id_token"


def test_build_oidc_client() -> None:
    http = make_http()
    secrets = EnvSecretProvider({"OPTI_SECRET_OIDC_CLIENT_SECRET": "s"})
    assert (
        build_oidc_client(OidcConfig(), http, secrets, public_base_url="https://ti.example") is None
    )
    cfg = OidcConfig(enabled=True, issuer="https://idp.example", client_id="opti")
    client = build_oidc_client(cfg, http, secrets, public_base_url="https://ti.example/")
    assert (
        client is not None and client.redirect_uri == "https://ti.example/api/v1/auth/oidc/callback"
    )


def test_redirect_follows_public_base_url() -> None:
    http = make_http()
    secrets = EnvSecretProvider({"OPTI_SECRET_OIDC_CLIENT_SECRET": "s"})
    cfg = OidcConfig(enabled=True, issuer="https://idp.example", client_id="opti")
    base = ["https://a.example"]
    client = build_oidc_client(cfg, http, secrets, public_base_url=lambda: base[0])
    assert (
        client is not None and client.redirect_uri == "https://a.example/api/v1/auth/oidc/callback"
    )
    base[0] = "https://b.example/"
    assert client.redirect_uri == "https://b.example/api/v1/auth/oidc/callback"
    fixed = build_oidc_client(
        cfg.model_copy(update={"redirect_uri": "https://idp-registered/cb"}),
        http,
        secrets,
        public_base_url=lambda: base[0],
    )
    assert fixed is not None and fixed.redirect_uri == "https://idp-registered/cb"
