from pathlib import Path

import pytest

from opti.settings import Settings


def test_defaults() -> None:
    s = Settings.from_env({})
    assert s.database_url is None and s.broker_url is None
    assert s.rules_path == Path("config/projects/example/keywords.yaml")
    assert s.alerting_config == Path("config/alerting.yaml")


def test_from_env() -> None:
    s = Settings.from_env(
        {
            "OPTI_DATABASE_URL": "postgresql+asyncpg://u:p@h/db",
            "OPTI_BROKER_URL": "redis://valkey:6379/0",
            "OPTI_CONFIG_DIR": "/etc/opti/connectors",
            "OPTI_STATE_DIR": "",
        }
    )
    assert s.database_url == "postgresql+asyncpg://u:p@h/db"
    assert s.broker_url == "redis://valkey:6379/0"
    assert s.config_dir == Path("/etc/opti/connectors")
    assert s.state_dir == Path("data")  # 空字符串视为未设置


def test_collector_and_gateway_settings() -> None:
    s = Settings.from_env(
        {
            "OPTI_COLLECTOR_MODE": "remote",
            "OPTI_REMOTE_TIMEOUT": "45",
            "OPTI_S3_ENDPOINT": "http://seaweedfs:8333",
            "OPTI_GATEWAY_PORT": "9443",
            "OPTI_GATEWAY_TLS_CERT": "/pki/gateway.pem",
            "OPTI_GATEWAY_NODES": "hk1, sg1",
        }
    )
    assert s.collector_mode == "remote" and s.remote_timeout == 45.0
    assert s.s3_endpoint == "http://seaweedfs:8333" and s.s3_bucket == "opti-evidence"
    assert s.gateway_port == 9443 and s.gateway_tls_cert == Path("/pki/gateway.pem")
    assert s.gateway_nodes == ("hk1", "sg1")
    assert Settings.from_env({}).collector_mode == "local"


def test_unknown_collector_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="OPTI_COLLECTOR_MODE"):
        Settings.from_env({"OPTI_COLLECTOR_MODE": "cloud"})


def test_api_settings() -> None:
    s = Settings.from_env(
        {"OPTI_API_PORT": "9000", "OPTI_COOKIE_SECURE": "false", "OPTI_SESSION_HOURS": "8",
         "OPTI_WEB_DIST": "/srv/web"}
    )  # fmt: skip
    assert s.api_port == 9000 and s.cookie_secure is False and s.session_hours == 8
    assert s.web_dist == Path("/srv/web")
    d = Settings.from_env({})
    assert d.cookie_secure is True and d.session_hours == 12 and d.api_host == "0.0.0.0"
    with pytest.raises(ValueError, match="OPTI_COOKIE_SECURE"):
        Settings.from_env({"OPTI_COOKIE_SECURE": "maybe"})


def test_organization_path() -> None:
    settings = Settings.from_env({"OPTI_ORGANIZATION": "/etc/opti/org.yaml"})
    assert settings.organization_path == Path("/etc/opti/org.yaml")
    assert not hasattr(settings, "report_contact_days")


def test_response_paths() -> None:
    s = Settings.from_env(
        {
            "OPTI_TAKEDOWN_CONFIG": "/etc/opti/platforms.yaml",
            "OPTI_TICKETS_CONFIG": "/etc/opti/t.yaml",
        }
    )
    assert s.takedown_config == Path("/etc/opti/platforms.yaml")
    assert s.tickets_config == Path("/etc/opti/t.yaml")
    assert Settings().takedown_templates == Path("config/takedown/templates")


def test_oidc_settings() -> None:
    s = Settings.from_env({"OPTI_OIDC_CONFIG": "/etc/opti/oidc.yaml", "OPTI_LOCAL_LOGIN": "false"})
    assert s.oidc_config == Path("/etc/opti/oidc.yaml") and s.local_login is False
    assert Settings().local_login is True


def test_vendor_list_path() -> None:
    assert Settings().vendors_path == Path("config/vendors.yaml")
    assert Settings.from_env({"OPTI_VENDORS": "/etc/opti/vendors.yaml"}).vendors_path == Path(
        "/etc/opti/vendors.yaml"
    )


def test_retention_config_path() -> None:
    s = Settings.from_env({"OPTI_RETENTION_CONFIG": "/etc/opti/retention.yaml"})
    assert s.retention_config == Path("/etc/opti/retention.yaml")
    assert Settings().retention_config == Path("config/retention.yaml")


def test_campaigns_config_path() -> None:
    assert Settings().campaigns_config == Path("config/campaigns.yaml")
    s = Settings.from_env({"OPTI_CAMPAIGNS_CONFIG": "/etc/opti/campaigns.yaml"})
    assert s.campaigns_config == Path("/etc/opti/campaigns.yaml")


def test_service_control_is_deployment_scoped_and_disabled_by_default() -> None:
    assert Settings.from_env({}).service_control_dir is None
    assert Settings.from_env(
        {"OPTI_SERVICE_CONTROL_DIR": "/run/opti-control"}
    ).service_control_dir == Path("/run/opti-control")
