import asyncio
import socket
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from opti.core.config import ProjectRules
from opti.enrichers.tls.enricher import TlsEnricher, fetch_certificate, parse_certificate
from opti.sdk.testing import make_context


def _self_signed(tmp_path: Path, cn: str = "sbr-loans.test") -> ssl.SSLContext:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Org"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName(f"www.{cn}")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


@pytest.fixture
async def tls_port(tmp_path: Path) -> AsyncIterator[int]:
    async def handler(_r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=_self_signed(tmp_path))
    yield server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()


async def test_fetch_and_parse(tls_port: int) -> None:
    der = await fetch_certificate("127.0.0.1", tls_port, server_name="sbr-loans.test")
    info = parse_certificate(der)
    assert info["issuer_o"] == "Evil Org"
    assert info["subject_cn"] == "sbr-loans.test"
    assert info["sans"] == ["sbr-loans.test", "www.sbr-loans.test"]
    assert info["self_signed"] is True
    assert len(info["sha256"]) == 64


async def test_enricher_handles_connection_refused(sbr_rules: ProjectRules) -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    e = TlsEnricher(
        make_context(sbr_rules, connector_id="tls"),
        {"port": port, "timeout": 2, "allow_private_targets": True},
    )
    out = await e.enrich("domain", "127.0.0.1")
    assert out["present"] is False and out["error"] == "ConnectionRefusedError"


@pytest.mark.parametrize("target", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "localhost"])
async def test_non_public_targets_are_blocked_by_default(
    sbr_rules: ProjectRules, target: str
) -> None:
    # 仿冒域名可能被解析到内网地址；在内网运行时不能替攻击者探测内网（SSRF）
    e = TlsEnricher(make_context(sbr_rules, connector_id="tls"), {"port": 443, "timeout": 2})
    assert await e.enrich("domain", target) == {
        "present": False,
        "error": "blocked_non_public_address",
    }
