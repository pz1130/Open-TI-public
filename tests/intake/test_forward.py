from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from opti.intake.forward import gateway_forwarder
from opti.sdk.models import RawItem
from opti.sdk.runtime import ConnectorBlocked


class Gateway:
    def __init__(self, accepted: int = 1) -> None:
        self.accepted = accepted
        self.items_seen: list[dict[str, Any]] = []
        self.closed = False

    async def items(self, items: list[dict[str, Any]]) -> int:
        self.items_seen.extend(items)
        return self.accepted

    async def aclose(self) -> None:
        self.closed = True


async def test_gateway_forward_waits_for_acceptance(monkeypatch: pytest.MonkeyPatch) -> None:
    gateway = Gateway(0)
    forward, close = gateway_forwarder(gateway)  # type: ignore[arg-type]
    item = RawItem("public_report", "r1", datetime.now(UTC), None, {})
    try:
        with pytest.raises(ConnectorBlocked, match="未接受"):
            await forward(item)
        gateway.accepted = 1
        await forward(item)
        assert len(gateway.items_seen) == 2
    finally:
        await close()
    assert gateway.closed


async def test_disabled_push_source_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "canary.yaml").write_text("enabled: false\nlicense_approved: true\n")
    monkeypatch.setenv("OPTI_CONFIG_DIR", str(tmp_path))
    gateway = Gateway()
    forward, close = gateway_forwarder(gateway)  # type: ignore[arg-type]
    try:
        with pytest.raises(ConnectorBlocked, match="disabled"):
            await forward(RawItem("canary", "c1", datetime.now(UTC), None, {}))
        assert gateway.items_seen == []
    finally:
        await close()
