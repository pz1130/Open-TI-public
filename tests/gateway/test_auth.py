import pytest

from opti.core.config import ProjectRules
from opti.gateway.auth import NodeAuth, overseas_rules, rules_digest
from opti.sdk.context import EnvSecretProvider

TOKEN = "a" * 40


def test_identify_by_bearer_token() -> None:
    auth = NodeAuth({"hk1": TOKEN, "sg1": "b" * 40})
    assert auth.identify(f"Bearer {TOKEN}") == "hk1"
    assert auth.identify(f"Bearer {'b' * 40}") == "sg1"
    assert auth.identify("Bearer wrong") is None
    assert auth.identify(TOKEN) is None
    assert auth.identify(None) is None


def test_tokens_come_from_secrets_and_must_be_long() -> None:
    auth = NodeAuth.from_secrets(
        ["hk1"], EnvSecretProvider({"OPTI_SECRET_GATEWAY_NODE_HK1": TOKEN})
    )
    assert auth.identify(f"Bearer {TOKEN}") == "hk1"
    with pytest.raises(ValueError, match="OPTI_SECRET_GATEWAY_NODE_HK1"):
        NodeAuth.from_secrets(["hk1"], EnvSecretProvider({"OPTI_SECRET_GATEWAY_NODE_HK1": "short"}))
    with pytest.raises(ValueError):
        NodeAuth.from_secrets([], EnvSecretProvider({}))


def test_rules_exclude_executives(sbr_rules: ProjectRules) -> None:
    data = sbr_rules.model_dump(mode="json")
    data["sets"]["executives"] = {
        "type": "executive", "approval_ref": "DPO-2026-01", "terms": ["Jane Example"],
    }  # fmt: skip
    rules = ProjectRules.model_validate(data)
    sent = overseas_rules(rules)
    assert "executives" not in sent["sets"]
    assert "Jane Example" not in str(sent)
    restored = ProjectRules.model_validate(sent)
    assert restored.domains == rules.domains
    assert set(restored.sets) == set(rules.sets) - {"executives"}
    assert rules_digest(sent) == rules_digest(overseas_rules(restored))
