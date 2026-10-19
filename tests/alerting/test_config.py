import pytest
from pydantic import ValidationError

from opti.alerting.config import AlertingConfig, Channel, secret_names
from opti.core.scoring import Severity

LEGACY = {
    "public_base_url": "https://ti.example/",
    "immediate": ["critical", "high"],
    "digest": ["medium"],
    "teams": {"enabled": True},
    "email": {
        "enabled": True,
        "smtp_host": "relay",
        "smtp_port": 587,
        "starttls": True,
        "sender": "ti@example.org",
        "recipients": ["soc@example.org"],
    },
}


def test_legacy_format_becomes_two_channels() -> None:
    cfg = AlertingConfig.model_validate(LEGACY)
    assert cfg.public_base_url == "https://ti.example"
    assert [(c.id, c.type) for c in cfg.channels] == [("teams", "teams"), ("email", "email")]
    assert cfg.channels[0].severities == (Severity.CRITICAL, Severity.HIGH)
    assert cfg.channels[1].recipients == ("soc@example.org",)
    assert all(c.reports == ("daily", "weekly", "monthly") and c.notices for c in cfg.channels)
    assert (cfg.smtp.host, cfg.smtp.port, cfg.smtp.sender) == ("relay", 587, "ti@example.org")
    assert secret_names(cfg) == {"smtp_username", "smtp_password", "channel:teams:webhook_url"}


def test_legacy_disabled_email_keeps_smtp_without_channel() -> None:
    cfg = AlertingConfig.model_validate({**LEGACY, "teams": {"enabled": False},
                                         "email": {**LEGACY["email"], "enabled": False}})  # fmt: skip
    assert cfg.channels == () and cfg.smtp.host == "relay"


@pytest.mark.parametrize(
    "channel",
    [
        {"id": "Bad", "name": "x", "type": "teams"},
        {"id": "ok", "name": "x", "type": "email", "enabled": True, "recipients": []},
        {"id": "ok", "name": "x", "type": "email", "recipients": ["not-an-email"]},
        {"id": "ok", "name": "x", "type": "teams", "recipients": ["a@b.org"]},
        {"id": "ok", "name": "x", "type": "teams", "severities": ["urgent"]},
    ],
)
def test_channel_validation(channel: dict) -> None:
    with pytest.raises(ValidationError):
        Channel.model_validate(channel)


def test_config_validation() -> None:
    dup = [{"id": "a", "name": "A", "type": "teams"}, {"id": "a", "name": "B", "type": "teams"}]
    with pytest.raises(ValidationError, match="重复"):
        AlertingConfig.model_validate({"channels": dup})
    with pytest.raises(ValidationError, match="访问地址"):
        AlertingConfig(public_base_url="ftp://ti.example")
    with pytest.raises(ValidationError, match="访问地址"):
        AlertingConfig(public_base_url="https://ti.example/?x=1")


def test_matches() -> None:
    c = Channel(
        id="brand",
        name="品牌",
        type="teams",
        severities=(Severity.HIGH,),
        categories=("negative_press",),
    )  # type: ignore[arg-type]
    assert c.matches("high", "negative_press")
    assert not c.matches("high", "phishing_site")
    assert not c.matches("critical", "negative_press")
    assert not c.model_copy(update={"enabled": False}).matches("high", "negative_press")
