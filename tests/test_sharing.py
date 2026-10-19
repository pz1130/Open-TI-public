from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from opti.core.scoring import Severity
from opti.settings import Settings
from opti.sharing import SharingConfig, SyslogChannel, load_sharing_config
from opti.siem import SyslogSender


def _self_signed_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pasted Test CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_defaults_and_repo_config(tmp_path: Path) -> None:
    assert load_sharing_config(tmp_path / "missing.yaml") == SharingConfig()
    cfg = load_sharing_config(Path("config/sharing.yaml"))
    assert cfg.stix.tlp == "amber" and cfg.stix.min_severity == Severity.MEDIUM
    assert not cfg.siem.syslog.enabled and not cfg.siem.webhook.enabled  # 仓库默认关闭
    assert Settings().sharing_config == Path("config/sharing.yaml")
    assert Settings.from_env(
        {"OPTI_SHARING_CONFIG": "/etc/opti/sharing.yaml"}
    ).sharing_config == Path("/etc/opti/sharing.yaml")


@pytest.mark.parametrize(
    "bad",
    [
        {"stix": {"tlp": "purple"}},
        {"siem": {"syslog": {"enabled": True}}},  # 缺少 host
        {"siem": {"syslog": {"enabled": True, "host": "siem.example", "protocol": "smtp"}}},
        {"siem": {"syslog": {"host": "siem.example", "port": 70000}}},
        {"siem": {"syslog": {"host": "siem.example", "app_name": "has space"}}},
        {"siem": {"webhook": {"enabled": True, "url": "ftp://siem.example/hook"}}},
        {"siem": {"webhook": {"format": "xml"}}},
    ],
)
def test_invalid(bad: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SharingConfig.model_validate(bad)


def test_pasted_ca_is_validated_and_used_before_file() -> None:
    pem = _self_signed_pem()
    channel = SyslogChannel(enabled=True, host="siem.example", ca_pem=pem, ca_file="/missing.pem")
    context = SyslogSender(channel).ssl_context()
    assert context is not None and context.get_ca_certs()
    assert context.check_hostname
    with pytest.raises(ValidationError, match="CA 证书"):
        SyslogChannel(enabled=True, host="siem.example", ca_pem="-----BEGIN CERTIFICATE-----\nnope")
