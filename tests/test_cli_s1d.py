from pathlib import Path

import pytest

from opti.cli import main


def test_pki_dev(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "pki"
    assert (
        main(
            [
                "pki-dev",
                "--out",
                str(out),
                "--server",
                "localhost",
                "--node",
                "hk1",
                "--node",
                "sg1",
            ]
        )
        == 0
    )
    for name in ("ca.pem", "gateway.pem", "gateway.key", "node-hk1.pem", "node-sg1.key"):
        assert (out / name).exists(), name
    assert "node-hk1" in capsys.readouterr().out


def test_gateway_refuses_to_start_without_mtls(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("OPTI_GATEWAY_TLS_CERT", "OPTI_GATEWAY_TLS_KEY", "OPTI_GATEWAY_CLIENT_CA"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(RuntimeError, match="mTLS"):
        main(["gateway"])


def test_collector_requires_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("OPTI_GATEWAY_URL", "OPTI_NODE_ID", "OPTI_SECRET_COLLECTOR_NODE_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValueError, match="OPTI_GATEWAY_URL"):
        main(["collector"])


def test_stream_is_refused_in_remote_mode(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPTI_DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:1/none")
    monkeypatch.setenv("OPTI_COLLECTOR_MODE", "remote")
    assert main(["stream", "certstream"]) == 2
    assert "OPTI_COLLECTOR_STREAMS" in capsys.readouterr().err
