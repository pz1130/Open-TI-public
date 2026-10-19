import asyncio

from opti.sandbox.proxy import pinned_proxy


async def _connect_proxy(
    port: int, host: str, target_port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00"
    encoded = host.encode("ascii")
    writer.write(
        b"\x05\x01\x00\x03" + bytes((len(encoded),)) + encoded + target_port.to_bytes(2, "big")
    )
    await writer.drain()
    return reader, writer


async def test_proxy_connects_to_validated_ip_without_client_dns() -> None:
    seen: list[bytes] = []

    async def site(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.append(await reader.read(1024))
        writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(site, "127.0.0.1", 0)
    target_port = server.sockets[0].getsockname()[1]

    async def resolve(host: str, port: int) -> list[str]:
        assert (host, port) == ("unresolvable.invalid", target_port)
        return ["127.0.0.1"]

    try:
        async with pinned_proxy(resolve=resolve, allow_private=True) as proxy:
            port = int(proxy.url.rsplit(":", 1)[1])
            reader, writer = await _connect_proxy(port, "unresolvable.invalid", target_port)
            assert (await reader.readexactly(10))[1] == 0
            writer.write(b"GET / HTTP/1.0\r\nHost: unresolvable.invalid\r\n\r\n")
            await writer.drain()
            assert b"200 OK" in await reader.read(1024)
            writer.close()
            await writer.wait_closed()
        assert seen and seen[0].startswith(b"GET /")
    finally:
        server.close()
        await server.wait_closed()


async def test_proxy_rejects_private_and_mixed_dns_answers() -> None:
    for addresses in (["127.0.0.1"], ["8.8.8.8", "10.0.0.1"]):
        blocked: list[str] = []

        async def resolve(_host: str, _port: int, answers: list[str] = addresses) -> list[str]:
            return answers

        async with pinned_proxy(resolve=resolve, blocked=blocked) as proxy:
            port = int(proxy.url.rsplit(":", 1)[1])
            reader, writer = await _connect_proxy(port, "example.com", 443)
            assert (await reader.readexactly(10))[1] == 2
            assert blocked == ["example.com:443"]
            writer.close()
            await writer.wait_closed()
