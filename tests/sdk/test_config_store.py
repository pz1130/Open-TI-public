from pathlib import Path

import pytest

from opti.sdk import config_store
from opti.sdk.context import EnvSecretProvider
from opti.sdk.registry import load_file_instance, load_instance_config

CONFIG_DIR = Path("config/connectors")
OTX = {
    "enabled": True,
    "license_approved": True,
    "license_ref": "LEGAL-1",
    "plan": "free",
    "config": {},
}


def test_without_current_settings_reads_yaml_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPTI_SECRET_OTX_API_KEY", "env-key")
    config_store.clear_current()
    assert load_instance_config(CONFIG_DIR, "otx") == load_file_instance(CONFIG_DIR, "otx")
    assert EnvSecretProvider().get("otx", "api_key") == "env-key"


def test_current_settings_replace_yaml_entry_and_stored_secrets_win(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPTI_SECRET_OTX_API_KEY", "env-key")
    monkeypatch.setenv("OPTI_SECRET_URLSCAN_API_KEY", "env-urlscan")
    config_store.set_current({"otx": OTX}, {"otx": {"api_key": "web-key"}})
    assert load_instance_config(CONFIG_DIR, "otx").license_ref == "LEGAL-1"
    assert load_instance_config(CONFIG_DIR, "crtsh") == load_file_instance(CONFIG_DIR, "crtsh")
    assert EnvSecretProvider().get("otx", "api_key") == "web-key"
    assert EnvSecretProvider().get("urlscan", "api_key") == "env-urlscan"  # 库中没有：环境变量兜底


def test_cleared_secret_masks_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPTI_SECRET_OTX_API_KEY", "env-key")
    config_store.set_current({}, {"otx": {"api_key": None}})
    assert EnvSecretProvider().get("otx", "api_key") is None
    assert config_store.managed_secrets("otx") == {"api_key": None}


def test_current_settings_are_copied(monkeypatch: pytest.MonkeyPatch) -> None:
    instances = {"otx": dict(OTX)}
    config_store.set_current(instances, {})
    instances["otx"]["enabled"] = False
    assert load_instance_config(CONFIG_DIR, "otx").enabled is True
