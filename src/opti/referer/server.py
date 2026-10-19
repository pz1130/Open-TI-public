"""syslog 接收（TCP，可选 TLS）：Web 服务器把访问日志实时发来，按窗口聚合后转交平台。"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from collections.abc import Awaitable, Callable

from opti.referer.logs import RefererAggregator, parse_line
from opti.sdk.models import RawItem

log = logging.getLogger("opti.referer")
Forward = Callable[[RawItem], Awaitable[None]]


class SyslogServer:
    def __init__(
        self,
        aggregator: RefererAggregator,
        forward: Forward,
        *,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext | None = None,
        flush_interval: float = 60.0,
        max_line: int = 16384,
        max_connections: int = 100,
    ) -> None:
        self._agg = aggregator
        self._forward = forward
        self._host, self._port = host, port
        self._ssl = ssl_context
        self._flush_interval = flush_interval
        self._max_line = max_line
        self._slots = asyncio.Semaphore(max_connections)
        self._server: asyncio.Server | None = None
        self._flusher: asyncio.Task[None] | None = None
        self.port = port
        self._handlers: set[asyncio.Task[None]] = set()
        self._pending: list[RawItem] = []
        self._flush_lock = asyncio.Lock()

    async def _frame(self, reader: asyncio.StreamReader) -> bytes | None:
        first = await reader.read(1)
        if not first:
            return None
        prefix = bytearray(first)
        if first.isdigit():
            while True:
                next_byte = await reader.read(1)
                if not next_byte:
                    return bytes(prefix)
                if next_byte.isdigit():
                    prefix.extend(next_byte)
                    if len(prefix) > 10:
                        raise ValueError("length prefix too long")
                    continue
                if next_byte == b" ":
                    length = int(prefix)
                    if not 0 < length <= self._max_line:
                        raise ValueError("frame too long")
                    return await reader.readexactly(length)
                prefix.extend(next_byte)
                if next_byte == b"\n":
                    return bytes(prefix)
                break
        data = bytes(prefix) + await reader.readline()
        if len(data) > self._max_line:
            raise ValueError("line too long")
        return data

    async def _frames(self, reader: asyncio.StreamReader) -> None:
        while (frame := await asyncio.wait_for(self._frame(reader), 60)) is not None:
            self._agg.add(parse_line(frame.decode("utf-8", "replace")))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._slots.locked():
            writer.close()
            return
        task = asyncio.current_task()
        if task is not None:
            self._handlers.add(task)
        async with self._slots:
            try:
                await self._frames(reader)
            except (
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
                ValueError,
                ConnectionError,
                TimeoutError,
            ):
                pass  # 畸形或超长数据：关闭连接
            finally:
                if task is not None:
                    self._handlers.discard(task)
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def flush_now(self, *, force: bool = True) -> None:
        async with self._flush_lock:
            # Retain unsent windows until forwarding succeeds.
            while self._pending:
                await self._forward(self._pending[0])
                self._pending.pop(0)
            self._pending.extend(self._agg.flush(force=force))
            while self._pending:
                await self._forward(self._pending[0])
                self._pending.pop(0)

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self._flush_interval)
            try:
                await self.flush_now(force=False)
            except Exception:  # 转交失败不能让接收服务退出；数据随下一个窗口重来
                log.warning("转交盗链数据失败，待下一轮重试")

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self._host, self._port, ssl=self._ssl, limit=self._max_line
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._flusher = asyncio.create_task(self._flush_loop())

    async def close(self) -> None:
        if self._flusher is not None:
            self._flusher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flusher
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

        for task in list(self._handlers):
            task.cancel()
        if self._handlers:
            await asyncio.gather(*self._handlers, return_exceptions=True)
