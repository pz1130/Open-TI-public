"""采集节点访问境内采集网关的客户端：mTLS + 节点令牌。

这是平台内部通道，不经 RateLimitedHttpClient（那是访问外部数据源用的）。
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx

from opti.collector import VERSION
from opti.core.secret_guard import mask_deep
from opti.gateway.jobs import KINDS, Job, JobKind


class GatewayError(Exception):
    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(
            f"网关请求失败（{status if status is not None else '网络错误'}）：{message}"
        )
        self.status = status

    @property
    def retriable(self) -> bool:
        return self.status is None or self.status == 429 or self.status >= 500


def mtls_context(ca: Path, cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


class GatewayClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        verify: ssl.SSLContext | bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._c = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}", "User-Agent": f"opti-collector/{VERSION}"},
            verify=verify,
            transport=transport,
            timeout=timeout,
        )

    async def aclose(self) -> None:
        await self._c.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            resp = await self._c.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise GatewayError(None, type(e).__name__) from e
        if resp.status_code >= 400:
            raise GatewayError(resp.status_code, resp.text[:200])
        return resp

    async def rules(self) -> tuple[str, dict[str, Any]]:
        body = (await self._request("GET", "/v1/rules")).json()
        return str(body["digest"]), dict(body["rules"])

    async def connector_config(
        self,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, str | None]]]:
        body = (await self._request("GET", "/v1/connector-config")).json()
        if "page_policy" in body:
            from opti.core import policy

            policy.install(
                policy.current().model_copy(
                    update={
                        "pages": policy.PagePolicy.model_validate(body["page_policy"]),
                    }
                )
            )
        return dict(body["instances"]), dict(body["secrets"])

    async def lease(self, wait: float, kinds: Sequence[JobKind] = KINDS) -> Job | None:
        resp = await self._request(
            "POST", "/v1/jobs/lease", json={"wait": wait, "kinds": list(kinds)}, timeout=wait + 15
        )
        if resp.status_code == 204:
            return None
        return Job.from_dict(resp.json())

    async def result(self, job_id: str, result: dict[str, Any]) -> None:
        await self._request("POST", f"/v1/jobs/{job_id}/result", json=mask_deep(result))

    async def items(self, items: list[dict[str, Any]]) -> int:
        resp = await self._request("POST", "/v1/items", json={"items": mask_deep(items)})
        return int(resp.json()["accepted"])

    async def upload_evidence(self, data: bytes, content_type: str) -> dict[str, Any]:
        params = {"sha256": hashlib.sha256(data).hexdigest(), "content_type": content_type}
        attempt = 0
        while True:
            try:
                return await self._upload_evidence(data, params)
            except GatewayError as e:
                if not e.retriable:
                    raise
                await asyncio.sleep(min(60.0, 2.0 ** min(attempt, 6)))
                attempt += 1

    async def _upload_evidence(self, data: bytes, params: dict[str, str]) -> dict[str, Any]:
        resp = await self._request(
            "PUT",
            "/v1/evidence",
            params=params,
            content=data,
            headers={"Content-Type": "application/octet-stream"},
        )
        return dict(resp.json())

    async def heartbeat(self, version: str, status: dict[str, Any]) -> None:
        await self._request("POST", "/v1/heartbeat", json={"version": version, "status": status})
