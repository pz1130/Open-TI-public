import pytest

from opti.cli import main


def test_canary_snippet(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("OPTI_SECRET_INTAKE_CANARY_TOKEN", "t" * 32)
    assert (
        main(
            [
                "--rules",
                "config/projects/sample-brand/keywords.yaml",
                "canary-snippet",
                "--base-url",
                "https://www.example.org/ti-intake",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "<script>" in out and "sbr.int" in out and "background-image" in out


def test_intake_requires_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPTI_SECRET_INTAKE_CANARY_TOKEN", raising=False)
    monkeypatch.delenv("OPTI_SECRET_INTAKE_REPORT_KEY", raising=False)
    with pytest.raises(ValueError, match="OPTI_SECRET_INTAKE"):
        main(["intake"])


def test_intake_rejects_database_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPTI_SECRET_INTAKE_CANARY_TOKEN", "t" * 32)
    monkeypatch.setenv("OPTI_SECRET_INTAKE_REPORT_KEY", "k" * 32)
    monkeypatch.setenv("OPTI_DATABASE_URL", "postgresql+asyncpg://unused/unused")
    with pytest.raises(ValueError, match="不得设置 OPTI_DATABASE_URL"):
        main(["intake"])


def test_edge_deployment_has_no_database_or_mail_credentials() -> None:
    from pathlib import Path

    import yaml

    config = yaml.safe_load(Path("deploy/compose.platform.yml").read_text())
    for service in ("intake", "syslog"):
        edge = config["services"][service]
        assert "env_file" not in edge
        assert not any(
            "DATABASE" in key or "MAILBOX" in key or "DMARC" in key for key in edge["environment"]
        )
        assert edge["ports"][0].startswith("127.0.0.1:")


def test_edge_deployment_receives_secret_mask_key() -> None:
    from pathlib import Path

    import yaml

    # 边缘入口不读 .env，但启动时要求遮蔽密钥（require_mask_key），必须单独传入
    config = yaml.safe_load(Path("deploy/compose.platform.yml").read_text())
    for service in ("intake", "syslog"):
        assert "OPTI_SECRET_MASK_KEY" in config["services"][service]["environment"]


def test_intake_invalid_token_fails_before_broker_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPTI_SECRET_INTAKE_CANARY_TOKEN", "invalid/" * 4)
    monkeypatch.setenv("OPTI_SECRET_INTAKE_REPORT_KEY", "k" * 32)
    with pytest.raises(ValueError, match="OPTI_SECRET_INTAKE"):
        main(["intake"])


def test_deployment_retains_sandbox_endpoint() -> None:
    from pathlib import Path

    import yaml

    platform = yaml.safe_load(Path("deploy/compose.platform.yml").read_text())
    collector = yaml.safe_load(Path("deploy/compose.collector.yml").read_text())
    assert (
        platform["services"]["worker"]["environment"]["OPTI_SANDBOX_URL"] == "http://browser:8000"
    )
    assert (
        collector["services"]["collector"]["environment"]["OPTI_SANDBOX_URL"]
        == "http://browser:8000"
    )
