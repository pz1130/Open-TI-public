"""按配置版本重建 OIDC 客户端，登录与凭据修改无需重启 API。"""

from __future__ import annotations

from collections.abc import Callable

from opti.api.oidc.client import OidcClient, build_oidc_client
from opti.configs.runtime import ConfigSnapshot
from opti.sdk.context import EnvSecretProvider
from opti.sdk.http import RateLimitedHttpClient


class ConfigBoundOidc:
    def __init__(self, snapshot: Callable[[], ConfigSnapshot], http: RateLimitedHttpClient) -> None:
        self._snapshot = snapshot
        self._http = http
        self._digest: str | None = None
        self._client: OidcClient | None = None

    def current(self) -> OidcClient | None:
        snapshot = self._snapshot()
        digest = snapshot.digest("identity")
        if digest != self._digest:
            self._client = build_oidc_client(
                snapshot.identity,
                self._http,
                EnvSecretProvider(
                    {
                        "OPTI_SECRET_OIDC_CLIENT_SECRET": snapshot.secrets("identity").get(
                            "client_secret"
                        )
                        or ""
                    }
                ),
                public_base_url=lambda: self._snapshot().alerting.public_base_url,
            )
            self._digest = digest
        return self._client
