"""测试用 OIDC 身份提供方：在 httpx.MockTransport 中提供发现文档、JWKS 与令牌端点（S2-D 各测试共用）。"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import parse_qsl

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from opti.api.oidc.client import s256


class FakeIdp:
    def __init__(
        self, issuer: str = "https://idp.example/realms/opti", client_id: str = "opti"
    ) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.kid = "k1"
        self.keys: dict[str, rsa.RSAPrivateKey] = {
            "k1": rsa.generate_private_key(public_exponent=65537, key_size=2048)
        }
        self.codes: dict[str, dict[str, Any]] = {}
        self.challenges: dict[str, str] = {}
        self.token_requests: list[dict[str, str]] = []
        self.jwks_fetches = 0
        self.discovery_overrides: dict[str, Any] = {}

    def rotate(self, kid: str) -> None:
        """换签名密钥：旧密钥从 JWKS 中移除。"""
        self.keys = {kid: rsa.generate_private_key(public_exponent=65537, key_size=2048)}
        self.kid = kid

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
            "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
            "jwks_uri": f"{self.issuer}/protocol/openid-connect/certs",
            "end_session_endpoint": f"{self.issuer}/protocol/openid-connect/logout",
            **self.discovery_overrides,
        }

    def jwks(self) -> dict[str, Any]:
        keys = []
        for kid, key in self.keys.items():
            jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
            keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": keys}

    def id_token(
        self,
        *,
        nonce: str,
        sub: str = "u-1",
        username: str | None = None,
        groups: tuple[str, ...] = (),
        aud: str | list[str] | None = None,
        iss: str | None = None,
        exp_delta: int = 300,
        alg: str = "RS256",
        kid: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": iss or self.issuer, "sub": sub, "aud": aud or self.client_id, "iat": now,
            "exp": now + exp_delta, "nonce": nonce, "preferred_username": username or f"{sub}@example.org",
            "name": "Test User", "email": f"{sub}@example.org", "groups": list(groups), **(extra or {}),
        }  # fmt: skip
        headers = {"kid": kid or self.kid}
        if alg.startswith("HS"):
            return jwt.encode(claims, "s" * 32, algorithm=alg, headers=headers)
        if alg == "none":
            return jwt.encode(claims, None, algorithm="none", headers=headers)  # type: ignore[arg-type]
        return jwt.encode(claims, self.keys[kid or self.kid], algorithm=alg, headers=headers)

    def issue(self, code: str, *, challenge: str, **token_kw: Any) -> None:
        """登记一个授权码：令牌端点只在 code_verifier 与 challenge 匹配时签发 ID Token。"""
        self.codes[code] = token_kw
        self.challenges[code] = challenge

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        d = self.discovery()
        if url == f"{self.issuer}/.well-known/openid-configuration":
            return httpx.Response(200, json=d)
        if url == d["jwks_uri"]:
            self.jwks_fetches += 1
            return httpx.Response(200, json=self.jwks())
        if url == d["token_endpoint"] and request.method == "POST":
            form = dict(parse_qsl(request.content.decode()))
            self.token_requests.append(form)
            code = form.get("code", "")
            if code not in self.codes or form.get("client_id") != self.client_id:
                return httpx.Response(400, json={"error": "invalid_grant"})
            if s256(form.get("code_verifier", "")) != self.challenges[code]:
                return httpx.Response(
                    400, json={"error": "invalid_grant", "error_description": "PKCE"}
                )
            kw = self.codes.pop(code)
            return httpx.Response(
                200,
                json={
                    "id_token": self.id_token(**kw),
                    "access_token": "at",
                    "token_type": "Bearer",
                },
            )
        return httpx.Response(404)
