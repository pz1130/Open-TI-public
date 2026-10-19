import asyncio

from opti.core.config import ProjectRules
from opti.referer.logs import RefererAggregator
from opti.referer.server import SyslogServer
from opti.sdk.models import RawItem

LINE = '1.2.3.4 - - [02/Oct/2026:08:00:00 +0000] "GET /logo.png HTTP/1.1" 200 1 "https://clone.top/" "UA"'


async def test_tcp_newline_and_octet_counting(sbr_rules: ProjectRules) -> None:
    sent: list[RawItem] = []

    async def forward(item: RawItem) -> None:
        sent.append(item)

    agg = RefererAggregator(sbr_rules, min_hits=3)
    server = SyslogServer(agg, forward, host="127.0.0.1", port=0, flush_interval=3600)
    await server.start()
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        msg = LINE.encode()
        writer.write(msg + b"\n" + msg + b"\n" + str(len(msg)).encode() + b" " + msg)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)
        await server.flush_now()
    finally:
        await server.close()
    assert [i.payload["indicators"][0]["volume"] for i in sent] == [3]


async def test_overlong_line_is_dropped(sbr_rules: ProjectRules) -> None:
    agg = RefererAggregator(sbr_rules, min_hits=1)
    sent: list[RawItem] = []

    async def forward(item: RawItem) -> None:
        sent.append(item)

    server = SyslogServer(agg, forward, host="127.0.0.1", port=0, max_line=100)
    await server.start()
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"x" * 1000 + b"\n" + LINE.encode() + b"\n")
        await writer.drain()
        writer.close()
        await asyncio.sleep(0.2)
        await server.flush_now()
    finally:
        await server.close()
    assert sent == []  # 超长行导致连接被关闭，其后的数据不处理


async def test_compact_json_newline_and_failed_flush_retry(sbr_rules: ProjectRules) -> None:
    import json

    sent: list[RawItem] = []
    fail = True

    async def forward(item: RawItem) -> None:
        nonlocal fail
        if fail:
            fail = False
            raise RuntimeError("queue unavailable")
        sent.append(item)

    server = SyslogServer(
        RefererAggregator(sbr_rules, min_hits=1), forward, host="127.0.0.1", port=0
    )
    await server.start()
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        raw = json.dumps(
            {"path": "/logo.png", "referer": "https://clone.top/private?q=personal", "status": 200},
            separators=(",", ":"),
        ).encode()
        writer.write(raw + b"\n" + raw + b"\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        import pytest

        with pytest.raises(RuntimeError):
            await server.flush_now()
        await server.flush_now()
        assert len(sent) == 1 and sent[0].payload["indicators"][0]["volume"] == 2
        assert "personal" not in str(sent[0].payload) and "private" not in str(sent[0].payload)
    finally:
        await server.close()
