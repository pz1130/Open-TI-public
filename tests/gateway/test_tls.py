import asyncio
import socket
import ssl
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import uvicorn

from opti.core.config import ProjectRules
from opti.gateway.app import create_gateway
from opti.gateway.pki import make_dev_pki
from opti.gateway.server import ssl_kwargs
from opti.gateway.testing import TOKEN, make_deps
from opti.settings import Settings


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
async def gateway(tmp_path: Path, sbr_rules: ProjectRules) -> AsyncIterator[tuple[str, Path]]:
    pki = tmp_path / "pki"
    make_dev_pki(pki, server_names=["localhost", "127.0.0.1"], nodes=["hk1"])
    settings = Settings(
        gateway_tls_cert=pki / "gateway.pem",
        gateway_tls_key=pki / "gateway.key",
        gateway_client_ca=pki / "ca.pem",
    )
    deps, _ = make_deps(sbr_rules)
    port = _free_port()
    config = uvicorn.Config(
        create_gateway(deps),
        host="127.0.0.1",
        port=port,
        log_level="warning",
        **ssl_kwargs(settings),
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)
    try:
        yield f"https://127.0.0.1:{port}", pki
    finally:
        server.should_exit = True
        await task


def _context(pki: Path, *, cert: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    if cert:
        ctx.load_cert_chain(str(pki / f"{cert}.pem"), str(pki / f"{cert}.key"))
    return ctx


async def test_tls_accepts_node_certificate(gateway: tuple[str, Path]) -> None:
    url, pki = gateway
    async with httpx.AsyncClient(verify=_context(pki, cert="node-hk1")) as c:
        r = await c.get(f"{url}/v1/rules", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200


async def test_tls_rejects_client_without_cert(gateway: tuple[str, Path]) -> None:
    url, pki = gateway
    async with httpx.AsyncClient(verify=_context(pki, cert=None)) as c:
        with pytest.raises(httpx.TransportError):
            await c.get(f"{url}/v1/rules", headers={"Authorization": f"Bearer {TOKEN}"})


async def test_tls_rejects_certificate_from_other_ca(
    gateway: tuple[str, Path], tmp_path: Path
) -> None:
    url, pki = gateway
    rogue = tmp_path / "rogue"
    make_dev_pki(rogue, server_names=["localhost"], nodes=["hk1"])
    ctx = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    ctx.load_cert_chain(str(rogue / "node-hk1.pem"), str(rogue / "node-hk1.key"))
    async with httpx.AsyncClient(verify=ctx) as c:
        with pytest.raises(httpx.TransportError):
            await c.get(f"{url}/v1/rules", headers={"Authorization": f"Bearer {TOKEN}"})


def test_private_keys_are_not_world_readable(tmp_path: Path) -> None:
    make_dev_pki(tmp_path, server_names=["localhost"], nodes=["hk1"])
    for name in ("ca.key", "gateway.key", "node-hk1.key"):
        assert (tmp_path / name).stat().st_mode & 0o077 == 0


def test_ssl_kwargs_require_all_files() -> None:
    with pytest.raises(RuntimeError, match="mTLS"):
        ssl_kwargs(Settings())
