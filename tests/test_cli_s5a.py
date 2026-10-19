import asyncio
import json
from pathlib import Path

import pytest

from opti.cli import amain, main


@pytest.mark.db
def test_export_stix_cli(db_url: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                         capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    monkeypatch.setenv("OPTI_DATABASE_URL", db_url)
    out = tmp_path / "bundle.json"
    assert main(["export-stix", "--days", "7", "--out", str(out)]) == 0
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle" and any(o["type"] == "identity" for o in bundle["objects"])
    assert "已导出" in capsys.readouterr().out


async def test_siem_test_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                 capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.read())
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    cfg = tmp_path / "sharing.yaml"
    cfg.write_text(f"siem:\n  syslog: {{enabled: true, host: 127.0.0.1, port: {port}, protocol: tcp}}\n",
                   encoding="utf-8")  # fmt: skip
    monkeypatch.setenv("OPTI_SHARING_CONFIG", str(cfg))
    async with server:
        assert await amain(["siem-test"]) == 0
        for _ in range(100):
            if received:
                break
            await asyncio.sleep(0.01)
    assert "syslog：已发送" in capsys.readouterr().out
    assert b"CEF:0|Open-TI|Open-TI|" in received[0] and b"opti-siem-test.invalid" in received[0]
    monkeypatch.setenv("OPTI_SHARING_CONFIG", str(tmp_path / "missing.yaml"))
    assert await amain(["siem-test"]) == 0
    assert "未启用" in capsys.readouterr().out
