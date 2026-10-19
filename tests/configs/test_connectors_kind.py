import pytest

from opti.configs import kinds
from opti.configs.connectors import ConnectorOverrides, credential_names


def test_empty_document_means_no_overrides() -> None:
    assert kinds.default("connectors") == ConnectorOverrides()
    assert kinds.parse("connectors", "").connectors == {}


def test_valid_override_round_trips() -> None:
    text = kinds.from_data(
        "connectors",
        {"connectors": {"otx": {"enabled": True, "plan": "free", "config": {}}}},
    )
    model = kinds.parse("connectors", text)
    assert model.connectors["otx"].enabled is True
    assert kinds.to_data("connectors", model)["connectors"]["otx"]["plan"] == "free"


@pytest.mark.parametrize(
    ("entry", "path"),
    [
        ({"no_such_source": {}}, "connectors.no_such_source"),
        ({"otx": {"plan": "gold"}}, "connectors.otx.plan"),
        ({"otx": {"config": {"max_queries": "many"}}}, "connectors.otx.config"),
        ({"otx": {"surprise": 1}}, "connectors.otx.surprise"),
    ],
)
def test_invalid_entries_are_located(entry: dict, path: str) -> None:
    with pytest.raises(kinds.ConfigInvalid) as error:
        kinds.from_data("connectors", {"connectors": entry})
    assert error.value.errors[0]["path"] == path


def test_approved_without_reference_is_accepted() -> None:
    # 文号只在批准接口里强制；InstanceConfig 本身不要求
    model = kinds.parse("connectors", "connectors:\n  otx:\n    license_approved: true\n")
    assert model.connectors["otx"].license_ref is None


def test_credential_names_cover_every_manifest() -> None:
    names = credential_names()
    assert "otx:api_key" in names and "urlscan:api_key" in names
    assert kinds.kind("connectors").secret_names is not None
    assert kinds.kind("connectors").secret_names(ConnectorOverrides()) == names
    assert kinds.kind("connectors").stored_only is True
