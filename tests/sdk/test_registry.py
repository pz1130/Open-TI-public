from pathlib import Path
from typing import Any

import pytest
import yaml

from opti.sdk.context import EnvSecretProvider
from opti.sdk.manifest import ConnectorManifest, ManifestError
from opti.sdk.registry import InstanceConfig, Registry, gate, load_instance_config
from opti.sdk.testing import EchoConnector

ECHO = {
    "id": "echo",
    "name": "Echo",
    "version": "0.1.0",
    "category": "ct",
    "kind": ["poll"],
    "tier": "free",
    "entrypoint": "opti.sdk.testing:EchoConnector",
}


def _root(tmp_path: Path, *manifests: tuple[str, dict[str, Any]]) -> Path:
    root = tmp_path / "connectors"
    for dirname, data in manifests:
        (root / dirname).mkdir(parents=True)
        (root / dirname / "connector.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return root


def test_registry_discovers_and_loads(tmp_path: Path) -> None:
    reg = Registry([_root(tmp_path, ("echo", ECHO))])
    assert [m.id for m in reg.manifests()] == ["echo"]
    assert reg.load_class("echo") is EchoConnector


def test_unknown_connector(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="未知连接器"):
        Registry([_root(tmp_path, ("echo", ECHO))]).manifest("nope")


def test_dirname_must_match_id(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="目录名"):
        Registry([_root(tmp_path, ("other", ECHO))])


def test_class_id_must_match_manifest(tmp_path: Path) -> None:
    data = {**ECHO, "id": "echo2"}
    reg = Registry([_root(tmp_path, ("echo2", data))])
    with pytest.raises(ManifestError, match="id"):
        reg.load_class("echo2")


def test_builtin_registry_loads() -> None:
    Registry().manifests()


def test_instance_config_defaults_to_disabled(tmp_path: Path) -> None:
    assert load_instance_config(tmp_path, "echo") == InstanceConfig()


def test_instance_config_rejects_unknown_fields(tmp_path: Path) -> None:
    (tmp_path / "echo.yaml").write_text("enabled: true\nlicence_approved: true\n")
    with pytest.raises(ManifestError, match="licence_approved"):
        load_instance_config(tmp_path, "echo")


def _m(**over: Any) -> ConnectorManifest:
    return ConnectorManifest.model_validate({**ECHO, **over})


NO_SECRETS = EnvSecretProvider({})


def test_gate_ok() -> None:
    g = gate(_m(), InstanceConfig(enabled=True, license_approved=True), NO_SECRETS)
    assert g.runnable and g.reason == "ok"


@pytest.mark.parametrize(
    ("manifest", "instance", "prefix"),
    [
        ({}, {"enabled": False, "license_approved": True}, "disabled"),
        ({}, {"enabled": True}, "license_not_approved"),
        ({"darkweb": True}, {"enabled": True, "license_approved": True}, "darkweb_not_approved"),
        ({}, {"enabled": True, "license_approved": True, "plan": "pro"}, "unknown_plan"),
        (
            {"credentials": [{"name": "api_key", "required": True}]},
            {"enabled": True, "license_approved": True},
            "unconfigured",
        ),
        (
            {"plans": {"free": {}, "pro": {"requires": ["api_key"]}},
             "credentials": [{"name": "api_key"}]},
            {"enabled": True, "license_approved": True, "plan": "pro"},
            "unconfigured",
        ),
    ],
)  # fmt: skip
def test_gate_blocks(manifest: dict[str, Any], instance: dict[str, Any], prefix: str) -> None:
    g = gate(_m(**manifest), InstanceConfig.model_validate(instance), NO_SECRETS)
    assert not g.runnable and g.reason.startswith(prefix)


def test_allow_unapproved_bypasses_license_only() -> None:
    inst = InstanceConfig(enabled=True)
    assert gate(_m(), inst, NO_SECRETS, allow_unapproved=True).runnable
    dark = gate(_m(darkweb=True), inst, NO_SECRETS, allow_unapproved=True)
    assert not dark.runnable and dark.reason.startswith("darkweb_not_approved")


def test_credentials_from_secrets_unblock() -> None:
    m = _m(credentials=[{"name": "api_key", "required": True}])
    secrets = EnvSecretProvider({"OPTI_SECRET_ECHO_API_KEY": "k"})
    assert gate(m, InstanceConfig(enabled=True, license_approved=True), secrets).runnable
