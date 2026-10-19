"""OIDC 授权码 + PKCE 客户端（设计文档 15、16）：发现文档、JWKS、换取并校验 ID Token、提取身份。

只使用 ID Token 中的声明，不调用 userinfo，不保存访问令牌与 ID Token。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import jwt
from jwt import PyJWK, PyJWKSet

from opti.api.oidc.config import OidcConfig
from opti.sdk.context import SecretProvider
from opti.sdk.http import HttpError, RateLimitedHttpClient

CALLBACK_PATH = "/api/v1/auth/oidc/callback"
DISCOVERY_TTL = 3600.0
JWKS_REFRESH_MIN = 300.0  # 未知签名密钥时最多每 5 分钟刷新一次 JWKS，防止被伪造的 kid 刷请求
_USERNAME = re.compile(r"^[a-z0-9._@+-]{1,128}$")


class OidcError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class Provider:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    username: str
    display_name: str
    email: str | None
    claim_values: tuple[str, ...]  # roles_claim 中的组 / 应用角色


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def s256(verifier: str) -> str:
    return _b64(hashlib.sha256(verifier.encode()).digest())


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)  # 86 个字符，在 RFC 7636 要求的 43–128 之内
    return verifier, s256(verifier)


def _with_query(url: str, params: dict[str, str]) -> str:
    return url + ("&" if "?" in url else "?") + urlencode(params)


def _supplier(value: str | Callable[[], str]) -> Callable[[], str]:
    if isinstance(value, str):
        fixed = value
        return lambda: fixed
    return value


class OidcClient:
    def __init__(
        self,
        cfg: OidcConfig,
        http: RateLimitedHttpClient,
        client_secret: str | None,
        *,
        redirect_uri: str | Callable[[], str],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = cfg
        self._redirect = _supplier(redirect_uri)
        self._http = http
        self._secret = client_secret
        self._clock = clock
        self._provider: Provider | None = None
        self._provider_at = 0.0
        self._jwks: list[PyJWK] | None = None
        self._jwks_at = 0.0

    @property
    def redirect_uri(self) -> str:
        return self._redirect()

    def _url(self, value: Any, what: str) -> str:
        url = str(value or "")
        try:
            parsed = urlsplit(url)
        except ValueError as e:
            raise OidcError("unavailable", f"{what} is not a valid endpoint URL") from e
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and self.cfg.allow_insecure_http
        ):
            raise OidcError("unavailable", f"{what} must use https")
        if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise OidcError("unavailable", f"{what} is not a valid endpoint URL")
        return url

    async def provider(self) -> Provider:
        if self._provider is not None and self._clock() - self._provider_at < DISCOVERY_TTL:
            return self._provider
        issuer = self.cfg.effective_issuer
        try:
            doc = (
                await self._http.get(
                    f"{issuer}/.well-known/openid-configuration", follow_redirects=False
                )
            ).json()
        except (HttpError, ValueError) as e:
            raise OidcError("unavailable", f"discovery failed: {type(e).__name__}") from e
        if not isinstance(doc, dict) or doc.get("issuer") != issuer:
            raise OidcError(
                "unavailable", "issuer in the discovery document does not match the configuration"
            )
        end_session = doc.get("end_session_endpoint")
        provider = Provider(
            issuer=issuer,
            authorization_endpoint=self._url(
                doc.get("authorization_endpoint"), "authorization_endpoint"
            ),
            token_endpoint=self._url(doc.get("token_endpoint"), "token_endpoint"),
            jwks_uri=self._url(doc.get("jwks_uri"), "jwks_uri"),
            end_session_endpoint=self._url(end_session, "end_session_endpoint")
            if end_session
            else None,
        )
        self._provider, self._provider_at = provider, self._clock()
        return provider

    def authorize_url(self, p: Provider, *, state: str, nonce: str, challenge: str) -> str:
        assert self.cfg.client_id is not None
        return _with_query(
            p.authorization_endpoint,
            {
                "response_type": "code",
                "client_id": self.cfg.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(self.cfg.scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

    async def exchange(self, p: Provider, code: str, verifier: str) -> str:
        assert self.cfg.client_id is not None
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.cfg.client_id,
            "code_verifier": verifier,
        }
        if self._secret:
            data["client_secret"] = self._secret
        try:
            resp = await self._http.post_form(p.token_endpoint, data)
            body = resp.json()
        except HttpError as e:
            raise OidcError(
                "token", f"token endpoint returned {e.status or 'a network error'}"
            ) from e
        except ValueError as e:
            raise OidcError("token", "token endpoint returned invalid JSON") from e
        token = body.get("id_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise OidcError("token", "no id_token in the token response")
        return token

    async def _load_jwks(self, p: Provider) -> None:
        try:
            doc = (await self._http.get(p.jwks_uri, follow_redirects=False)).json()
        except (HttpError, ValueError) as e:
            raise OidcError("unavailable", f"JWKS fetch failed: {type(e).__name__}") from e
        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            raise OidcError("unavailable", "JWKS is not a key set")
        keys = [k for k in doc["keys"] if isinstance(k, dict) and k.get("use", "sig") == "sig"]
        try:
            self._jwks = list(PyJWKSet.from_dict({"keys": keys}).keys)
        except jwt.PyJWTError as e:
            raise OidcError("unavailable", "JWKS contains no usable signing key") from e
        self._jwks_at = self._clock()

    def _find(self, kid: str | None) -> PyJWK | None:
        keys = self._jwks or []
        if kid is None:
            return keys[0] if len(keys) == 1 else None
        return next((k for k in keys if k.key_id == kid), None)

    async def _key(self, p: Provider, kid: str | None) -> PyJWK:
        if self._jwks is None:
            await self._load_jwks(p)
        key = self._find(kid)
        if key is None and self._clock() - self._jwks_at >= JWKS_REFRESH_MIN:
            await self._load_jwks(p)  # 身份提供方轮换了签名密钥
            key = self._find(kid)
        if key is None:
            raise OidcError("id_token", "signing key not found")
        return key

    async def validate(self, p: Provider, id_token: str, nonce: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as e:
            raise OidcError("id_token", "malformed id_token") from e
        alg = header.get("alg")
        if alg not in self.cfg.allowed_algs:
            raise OidcError("id_token", f"signing algorithm {alg!r} is not allowed")
        key = await self._key(p, header.get("kid"))
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key.key,
                algorithms=[alg],
                audience=self.cfg.client_id,
                issuer=p.issuer,
                leeway=self.cfg.clock_skew_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as e:
            raise OidcError("id_token", f"invalid id_token: {type(e).__name__}") from e
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.cfg.client_id:
            raise OidcError("id_token", "azp does not match the client")
        got = claims.get("nonce")
        if not isinstance(got, str) or not hmac.compare_digest(got, nonce):
            raise OidcError("id_token", "nonce mismatch")
        if self.cfg.provider == "entra" and claims.get("tid") != self.cfg.tenant_id:
            raise OidcError("id_token", "tenant mismatch")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise OidcError("id_token", "subject is empty")
        return claims

    def identity(self, claims: dict[str, Any]) -> Identity:
        overage = claims.get("_claim_names")
        if isinstance(overage, dict) and self.cfg.roles_claim in overage:
            raise OidcError("too_many_groups", "group overage: use app roles instead of groups")
        raw = claims.get(self.cfg.username_claim)
        username = raw.strip().lower() if isinstance(raw, str) else ""
        if not _USERNAME.fullmatch(username):
            raise OidcError("id_token", f"claim {self.cfg.username_claim} is missing or unusable")
        values = claims.get(self.cfg.roles_claim) or []
        if isinstance(values, str):
            values = [values]
        claim_values = tuple(sorted({str(v) for v in values if isinstance(v, str | int)}))
        name = claims.get(self.cfg.display_name_claim)
        email = claims.get(self.cfg.email_claim)
        return Identity(
            issuer=str(claims["iss"]),
            subject=str(claims["sub"]),
            username=username,
            display_name=name.strip()[:200] if isinstance(name, str) else "",
            email=email[:320] if isinstance(email, str) else None,
            claim_values=claim_values,
        )

    def logout_url(self, p: Provider) -> str | None:
        if not p.end_session_endpoint or not self.cfg.client_id:
            return None
        params = {"client_id": self.cfg.client_id}
        if self.cfg.post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = self.cfg.post_logout_redirect_uri
        return _with_query(p.end_session_endpoint, params)


def build_oidc_client(
    cfg: OidcConfig,
    http: RateLimitedHttpClient,
    secrets: SecretProvider,
    *,
    public_base_url: str | Callable[[], str],
) -> OidcClient | None:
    if not cfg.enabled:
        return None
    base = _supplier(public_base_url)
    redirect: str | Callable[[], str] = cfg.redirect_uri or (
        lambda: f"{base().rstrip('/')}{CALLBACK_PATH}"
    )
    return OidcClient(cfg, http, secrets.get("oidc", "client_secret"), redirect_uri=redirect)
