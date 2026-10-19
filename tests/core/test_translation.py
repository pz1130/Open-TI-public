import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx
import pytest

from opti.translation import LocalTranslator, TranslationError


async def test_uses_only_local_unix_socket() -> None:
    requests: list[dict[str, object]] = []

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        headers = await reader.readuntil(b"\r\n\r\n")
        size = int(
            next(
                line.split(b":", 1)[1]
                for line in headers.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
        )
        requests.append(json.loads(await reader.readexactly(size)))
        body = json.dumps({"translatedText": ["银行批准贷款", "机构回应声明"]}).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    with TemporaryDirectory(dir="/tmp", prefix="opti-translation-") as short_dir:
        socket = Path(short_dir) / "translate.sock"
        server = await asyncio.start_unix_server(serve, path=str(socket))
        try:
            translator = LocalTranslator(socket)
            try:
                result = await translator.translate(
                    ["Bank approves loan", "Agency statement"], source="en", target="zh"
                )
            finally:
                await translator.close()
        finally:
            server.close()
            await server.wait_closed()
    assert result == ["银行批准贷款", "机构回应声明"]
    assert requests == [
        {
            "q": ["Bank approves loan", "Agency statement"],
            "source": "en",
            "target": "zh",
            "format": "text",
        }
    ]


async def test_rejects_redirects_oversized_and_malformed_results(tmp_path: Path) -> None:
    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://outside.example/translate"})

    translator = LocalTranslator(tmp_path / "unused.sock", transport=httpx.MockTransport(redirect))
    try:
        with pytest.raises(TranslationError):
            await translator.translate(["hello world"], source="en", target="zh")
    finally:
        await translator.close()

    for payload in ({"translatedText": ["x" * 33_000]}, {"translatedText": [1]}):
        transport = httpx.MockTransport(
            lambda _request, result=payload: httpx.Response(200, json=result)
        )
        translator = LocalTranslator(tmp_path / "unused.sock", transport=transport)
        try:
            with pytest.raises(TranslationError):
                await translator.translate(["hello world"], source="en", target="zh")
        finally:
            await translator.close()


async def test_rejects_invalid_request_without_contacting_service(tmp_path: Path) -> None:
    calls = 0

    def respond(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"translatedText": ["ok"]})

    translator = LocalTranslator(tmp_path / "unused.sock", transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(ValueError):
            await translator.translate(["hello"], source="auto", target="zh")
        with pytest.raises(ValueError):
            await translator.translate(["hello"], source="en", target="en")
        with pytest.raises(ValueError):
            await translator.translate(["x" * 4_001], source="en", target="zh")
    finally:
        await translator.close()
    assert calls == 0
