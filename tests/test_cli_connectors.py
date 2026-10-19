import json
from pathlib import Path

import pytest
import yaml
from websockets.asyncio.server import ServerConnection, serve

from opti.cli import amain, main
from opti.sdk.testing import cert_msg


def test_connectors_lists_builtins(
    sbr_rules_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--rules", str(sbr_rules_path), "connectors"]) == 0
    rows = {r["id"]: r for r in map(json.loads, capsys.readouterr().out.splitlines())}
    assert {
        "certstream",
        "own_domain_ct",
        "crtsh",
        "dnstwist",
        "nrd",
        "dns",
        "tls",
        "rdap",
        "tranco",
    } <= set(rows)
    assert rows["certstream"]["runnable"] is True
    assert rows["nrd"]["runnable"] is False
    assert rows["nrd"]["reason"].startswith("license_not_approved")


def test_collect_blocked_exits_3(sbr_rules_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--rules", str(sbr_rules_path), "collect", "nrd", "--max-items", "1"]) == 3
    assert "license_not_approved" in capsys.readouterr().err


def test_unknown_connector_exits_2(
    sbr_rules_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--rules", str(sbr_rules_path), "enrich", "nope", "x.com"]) == 2
    assert "未知连接器" in capsys.readouterr().err


async def test_collect_certstream_end_to_end(
    sbr_rules_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    async def handler(ws: ServerConnection) -> None:
        await ws.send(cert_msg(["crossbrace.com"], sha="s1"))
        await ws.send(cert_msg(["sbr-loans.com"], sha="p1"))

    async with serve(handler, "127.0.0.1", 0) as server:
        port = next(iter(server.sockets)).getsockname()[1]
        cfg = tmp_path / "config"
        cfg.mkdir()
        (cfg / "certstream.yaml").write_text(
            yaml.safe_dump(
                {
                    "enabled": True,
                    "license_approved": True,
                    "config": {"url": f"ws://127.0.0.1:{port}/", "max_reconnects": 0},
                }
            )
        )
        rc = await amain(
            ["--rules", str(sbr_rules_path), "--config-dir", str(cfg),
             "--state-dir", str(tmp_path / "data"), "collect", "certstream", "--seconds", "5"]
        )  # fmt: skip
    assert rc == 0
    rows = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [r["source_item_id"] for r in rows] == ["p1"]
    assert rows[0]["scores"][0]["domain"] == "sbr-loans.com"
    assert rows[0]["scores"][0]["severity"] == "medium"
