import json
from pathlib import Path

import pytest

from opti.cli import amain


async def test_vendors_test(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    vendors = tmp_path / "vendors.yaml"
    vendors.write_text(
        "vendors:\n  - {id: acme, name: Acme Holdings Ltd, domains: [acme.example], tier: high, owner: 采购部}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPTI_VENDORS", str(vendors))
    assert await amain(["vendors-test", "ACME Inc."]) == 0
    [hit] = json.loads(capsys.readouterr().out)
    assert hit == {"kind": "vendor", "id": "acme", "name": "Acme Holdings Ltd", "tier": "high", "owner": "采购部",
                   "how": "name", "detail": "acme"}  # fmt: skip
    assert await amain(["vendors-test", "Unrelated", "--domain", "www.acme.example"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["how"] == "domain"
    assert await amain(["vendors-test", "Nobody"]) == 0
    assert json.loads(capsys.readouterr().out) == []
