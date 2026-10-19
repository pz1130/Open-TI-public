from pathlib import Path

import pytest

from opti.configs import kinds
from opti.core.config import ProjectRules
from opti.organization import Organization
from opti.settings import Settings


def test_rules_round_trip(sbr_rules: ProjectRules) -> None:
    text = kinds.from_data("rules", kinds.to_data("rules", sbr_rules))
    assert kinds.parse("rules", text) == sbr_rules


def test_rules_errors_have_paths(sbr_rules: ProjectRules) -> None:
    data = kinds.to_data("rules", sbr_rules)
    data["sets"]["brand"]["terms"][0]["value"] = ""
    with pytest.raises(kinds.ConfigInvalid) as e:
        kinds.from_data("rules", data)
    assert e.value.errors[0]["path"] == "sets.brand.terms[0].value"


def test_rules_yaml_syntax_error_has_line() -> None:
    with pytest.raises(kinds.ConfigInvalid) as e:
        kinds.parse("rules", "project: a\nsets: [\n")
    assert e.value.errors[0]["line"] is not None


def test_organization_yaml_syntax_error_has_line() -> None:
    with pytest.raises(kinds.ConfigInvalid) as e:
        kinds.parse("organization", "name: [\n")
    assert e.value.errors[0]["line"] is not None


def test_rules_reject_aliases_unless_from_file(sbr_rules_path: Path) -> None:
    text = sbr_rules_path.read_text(encoding="utf-8") + "\nx: &a 1\n"
    with pytest.raises(kinds.ConfigInvalid, match="锚点"):
        kinds.parse("rules", text)


def test_size_and_control_characters() -> None:
    with pytest.raises(kinds.ConfigInvalid, match="KB"):
        kinds.parse("organization", "name: " + "a" * 16_001)
    with pytest.raises(kinds.ConfigInvalid, match="控制字符"):
        kinds.parse("organization", "name: a\x07\n")


def test_organization_round_trip_and_field_error() -> None:
    org = Organization(name="Acme", website="https://acme.test")
    assert (
        kinds.parse(
            "organization", kinds.from_data("organization", kinds.to_data("organization", org))
        )
        == org
    )
    with pytest.raises(kinds.ConfigInvalid) as e:
        kinds.from_data("organization", {"name": "Acme", "nick": "x"})
    assert e.value.errors[0]["path"] == "nick"


def test_read_file(tmp_path: Path, sbr_rules_path: Path) -> None:
    settings = Settings(rules_path=sbr_rules_path, organization_path=tmp_path / "missing.yaml")
    assert kinds.read_file("organization", settings) == ""
    assert kinds.read_file("rules", settings) == sbr_rules_path.read_text(encoding="utf-8")
    assert kinds.digest_of("a") == kinds.digest_of("a") != kinds.digest_of("b")


def test_alerting_kind(tmp_path: Path) -> None:
    legacy = "immediate: [high]\nteams:\n  enabled: true\n"
    cfg = kinds.parse("alerting", legacy, allow_aliases=True)
    assert [c.id for c in cfg.channels] == ["teams"]  # type: ignore[union-attr]
    text = kinds.from_data("alerting", kinds.to_data("alerting", cfg))
    assert "channels:" in text and kinds.parse("alerting", text) == cfg
    assert kinds.parse("alerting", "").channels == ()  # type: ignore[union-attr]
    with pytest.raises(kinds.ConfigInvalid) as e:
        kinds.from_data("alerting", {"channels": [{"id": "Bad", "name": "x", "type": "teams"}]})
    assert e.value.errors[0]["path"].startswith("channels[0]")
    settings = Settings(alerting_config=tmp_path / "missing.yaml")
    assert kinds.read_file("alerting", settings) == ""
