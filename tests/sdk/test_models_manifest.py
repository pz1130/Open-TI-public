from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from opti.sdk.manifest import (
    ConnectorManifest,
    ManifestError,
    RateLimit,
    load_manifest,
    validate_instance_config,
)
from opti.sdk.models import RawItem, Tier


def _item(connector_id: str, source_id: str) -> RawItem:
    return RawItem(connector_id, source_id, datetime(2026, 10, 2, tzinfo=UTC), None, {})


def test_item_id_is_deterministic() -> None:
    assert _item("a", "1").item_id == _item("a", "1").item_id
    assert _item("a", "1").item_id != _item("b", "1").item_id
    assert len(_item("a", "1").item_id) == 64


def _manifest_dict(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "echo",
        "name": "Echo",
        "version": "0.1.0",
        "category": "ct",
        "kind": ["poll"],
        "tier": "free",
        "entrypoint": "opti.sdk.testing:EchoConnector",
        "config_schema": {
            "type": "object",
            "properties": {
                "items": {"type": "array", "default": []},
                "delay": {"type": "number", "minimum": 0, "default": 0},
            },
            "additionalProperties": False,
        },
    }
    base.update(over)
    return base


def _write(tmp_path: Path, data: dict[str, Any]) -> Path:
    p = tmp_path / "connector.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


def test_load_manifest(tmp_path: Path) -> None:
    m = load_manifest(_write(tmp_path, _manifest_dict()))
    assert m.id == "echo" and m.tier == Tier.FREE
    assert m.egress == "overseas" and m.commercial_use == "unknown"
    assert "free" in m.plans


@pytest.mark.parametrize(
    ("override", "fragment"),
    [
        ({"id": "Bad-Id"}, "id"),
        ({"kind": []}, "kind"),
        ({"entrypoint": "no_colon"}, "entrypoint"),
        ({"requires_tor": True}, "requires_tor"),
        ({"config_schema": {"type": "no-such-type"}}, "config_schema"),
        ({"unknown_field": 1}, "unknown_field"),
    ],
)
def test_invalid_manifests(tmp_path: Path, override: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ManifestError, match=fragment):
        load_manifest(_write(tmp_path, _manifest_dict(**override)))


def test_tor_allowed_for_darkweb(tmp_path: Path) -> None:
    m = load_manifest(_write(tmp_path, _manifest_dict(requires_tor=True, darkweb=True)))
    assert m.requires_tor and m.darkweb


def test_validate_instance_config_fills_defaults() -> None:
    m = ConnectorManifest.model_validate(_manifest_dict())
    assert validate_instance_config(m, {}) == {"items": [], "delay": 0}


def test_validate_instance_config_rejects_bad_values() -> None:
    m = ConnectorManifest.model_validate(_manifest_dict())
    with pytest.raises(ManifestError, match="delay"):
        validate_instance_config(m, {"delay": -1})
    with pytest.raises(ManifestError, match="Additional properties"):
        validate_instance_config(m, {"nope": 1})


def test_defaults_are_not_shared_between_calls() -> None:
    m = ConnectorManifest.model_validate(_manifest_dict())
    first = validate_instance_config(m, {})
    first["items"].append("x")
    assert validate_instance_config(m, {})["items"] == []


def test_rate_limit_conversion() -> None:
    assert RateLimit(per_minute=6).requests_per_second() == pytest.approx(0.1)
    assert RateLimit(per_second=2, per_minute=60).requests_per_second() == pytest.approx(1.0)
    assert RateLimit().requests_per_second() is None
