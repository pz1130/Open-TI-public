from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from opti.takedown.templates import (
    TakedownTemplates,
    dump_templates,
    template_errors,
    templates_from_dir,
)

TEMPLATES = Path(__file__).resolve().parents[2] / "config" / "takedown" / "templates"


def test_builtin_templates_round_trip() -> None:
    templates = templates_from_dir(TEMPLATES)
    assert templates.text("zh-CN", "cdn").startswith("Subject:")
    text = dump_templates(templates.data())
    assert "zh-CN:" in text and "cdn: |" in text
    assert TakedownTemplates.model_validate(yaml.safe_load(text)) == templates


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("no subject\n$domain", "Subject:"),
        ("Subject: x\n$domian", "未知的占位符：$domian"),
        ("Subject: x\n${org_nam}", "未知的占位符：$org_nam"),
        ("Subject: x\ncost $5", "$$"),
    ],
)
def test_unknown_placeholder_rejected(text: str, message: str) -> None:
    assert any(message in error for error in template_errors(text))


def test_escaped_dollar_and_known_placeholders_are_valid() -> None:
    assert template_errors("Subject: $org_short_name $date\ncost $$5 ${domain}") == []


def test_validation_reports_language_and_kind() -> None:
    data = templates_from_dir(TEMPLATES).data()
    data["en-US"]["report"] = "Subject: x\n$bogus"
    with pytest.raises(ValidationError) as error:
        TakedownTemplates.model_validate(data)
    assert error.value.errors()[0]["loc"] == ("en-US", "report")
