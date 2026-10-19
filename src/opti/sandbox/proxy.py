"""截图浏览器专用 SOCKS5 出站代理：检查 DNS 后连接经验证的 IP。"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress

from opti.enrichers.http_probe.enricher import is_public_address, resolve_addresses

Resolver = Callable[[str, int], Awaitable[list[str]]]
MAX_TUNNEL_BYTES = 20 * 1024 * 1024
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
MAX_CONNECTIONS = 32


class PinnedSocksProxy:
    def __init__(
        self,
        *,
        resolve: Resolver = resolve_addresses,
        allow_private: bool = False,
        blocked: list[str] | None = None,
    ) -> None:
        self._resolve = resolve
        self._allow_private = allow_private
        self._blocked = blocked if blocked is not None else []
        self._slots = asyncio.Semaphore(MAX_CONNECTIONS)
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("proxy not started")
        port = self._server.sockets[0].getsockname()[1]
        return f"socks5://127.0.0.1:{port}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _read(self, reader: asyncio.StreamReader, size: int) -> bytes:
        return await asyncio.wait_for(reader.readexactly(size), READ_TIMEOUT)

    async def _target(self, reader: asyncio.StreamReader) -> tuple[str, int] | None:
        header = await self._read(reader, 4)
        if header[:3] != b"\x05\x01\x00":
            return None  # SOCKS5 CONNECT only
        if header[3] == 1:
            host = socket.inet_ntop(socket.AF_INET, await self._read(reader, 4))
        elif header[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, await self._read(reader, 16))
        elif header[3] == 3:
            length = (await self._read(reader, 1))[0]
            if not 1 <= length <= 253:
                return None
            host = (await self._read(reader, length)).decode("ascii")
        else:
            return None
        port = int.from_bytes(await self._read(reader, 2), "big")
        return (host, port) if port else None

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, code: int) -> None:
        writer.write(bytes((5, code, 0, 1, 0, 0, 0, 0, 0, 0)))
        await writer.drain()

    @staticmethod
    async def _pipe(source: asyncio.StreamReader, target: asyncio.StreamWriter) -> None:
        total = 0
        while chunk := await source.read(64 * 1024):
            total += len(chunk)
            if total > MAX_TUNNEL_BYTES:
                break
            target.write(chunk)
            await target.drain()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        remote: asyncio.StreamWriter | None = None
        pipes: set[asyncio.Task[None]] = set()
        try:
            async with self._slots:
                greeting = await self._read(reader, 2)
                if greeting[0] != 5 or not 1 <= greeting[1] <= 8:
                    return
                methods = await self._read(reader, greeting[1])
                if 0 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                writer.write(b"\x05\x00")
                await writer.drain()
                target = await self._target(reader)
                if target is None:
                    await self._reply(writer, 7)
                    return
                host, port = target
                try:
                    addresses = await asyncio.wait_for(self._resolve(host, port), CONNECT_TIMEOUT)
                except (OSError, TimeoutError):
                    addresses = []
                if not addresses or (
                    not self._allow_private and not all(map(is_public_address, addresses))
                ):
                    self._blocked.append(f"{host}:{port}")
                    await self._reply(writer, 2)
                    return
                try:
                    upstream, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(addresses[0], port), CONNECT_TIMEOUT
                    )
                except (OSError, TimeoutError):
                    self._blocked.append(f"{host}:{port}")
                    await self._reply(writer, 5)
                    return
                remote = remote_writer
                await self._reply(writer, 0)
                pipes = {
                    asyncio.create_task(self._pipe(reader, remote_writer)),
                    asyncio.create_task(self._pipe(upstream, writer)),
                }
                done, pending = await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
                for pipe in pending:
                    pipe.cancel()
                await asyncio.gather(*done, *pending, return_exceptions=True)
        except (OSError, UnicodeError, asyncio.IncompleteReadError, TimeoutError):
            pass
        finally:
            for pipe in pipes:
                if not pipe.done():
                    pipe.cancel()
            if pipes:
                await asyncio.gather(*pipes, return_exceptions=True)
            if remote is not None:
                remote.close()
                with suppress(OSError):
                    await remote.wait_closed()
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()
            if task is not None:
                self._tasks.discard(task)


@asynccontextmanager
async def pinned_proxy(
    *,
    resolve: Resolver = resolve_addresses,
    allow_private: bool = False,
    blocked: list[str] | None = None,
) -> AsyncIterator[PinnedSocksProxy]:
    proxy = PinnedSocksProxy(resolve=resolve, allow_private=allow_private, blocked=blocked)
    await proxy.start()
    try:
        yield proxy
    finally:
        await proxy.close()
