from pathlib import Path

import pytest

from opti.cli import amain


async def test_software_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "software.yaml"
    good = "software:\n  - {id: vpn, vendor: Example Networks, products: [EdgeGate VPN], tier: critical}\n"
    path.write_text(good, encoding="utf-8")
    monkeypatch.setenv("OPTI_SOFTWARE", str(path))
    assert await amain(["software-check"]) == 0
    assert "1 个软件" in capsys.readouterr().out
    bad = "software:\n  - {id: vpn, vendor: Example Networks, products: []}\n"
    path.write_text(bad, encoding="utf-8")
    assert await amain(["software-check"]) == 2
    assert "软件清单有误" in capsys.readouterr().err
