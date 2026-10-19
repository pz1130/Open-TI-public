import json
import logging
from pathlib import Path

import pytest

from opti.core.config import ProjectRules
from opti.sdk.context import EnvSecretProvider, JsonFileCursorStore, MemoryCursorStore, mask
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import EchoConnector, make_context


def test_env_secret_provider() -> None:
    p = EnvSecretProvider({"OPTI_SECRET_URLSCAN_API_KEY": "abc"})
    assert p.get("urlscan", "api_key") == "abc"
    assert p.get("urlscan", "other") is None


def test_mask() -> None:
    assert mask("supersecretvalue1234") == "****1234"
    assert mask("short") == "****"


def test_secret_values_are_redacted_in_logs(
    sbr_rules: ProjectRules, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "sk-live-0123456789abcd"  # gitleaks:allow  测试用假密钥
    ctx = make_context(
        sbr_rules,
        connector_id="redact_test",
        secrets=EnvSecretProvider({"OPTI_SECRET_REDACT_TEST_API_KEY": secret}),
    )
    with caplog.at_level(logging.INFO, logger="opti.connector.redact_test"):
        assert ctx.secret("api_key") == secret
        ctx.logger().info("calling with key=%s", secret)
    assert secret not in caplog.text
    assert "****abcd" in caplog.text
    assert "读取密钥 api_key" in caplog.text


def test_memory_cursor_store() -> None:
    s = MemoryCursorStore()
    assert s.get("c", "k") is None
    s.set("c", "k", "1")
    assert s.get("c", "k") == "1"


def test_json_file_cursor_store_persists(tmp_path: Path) -> None:
    path = tmp_path / "state" / "cursors.json"
    JsonFileCursorStore(path).set("crtsh", "max_id:sbr%", "42")
    assert JsonFileCursorStore(path).get("crtsh", "max_id:sbr%") == "42"
    assert json.loads(path.read_text(encoding="utf-8")) == {"crtsh": {"max_id:sbr%": "42"}}
    assert not path.with_suffix(".json.tmp").exists()


def test_context_cursors(sbr_rules: ProjectRules) -> None:
    ctx = make_context(sbr_rules, connector_id="c")
    ctx.set_cursor("k", "v")
    assert ctx.get_cursor("k") == "v"


def test_query_plan_excludes_local_only_terms(sbr_rules: ProjectRules) -> None:
    plan = build_query_plan(sbr_rules)
    values = {t.value for t in plan.terms}
    assert "Sample Brand" in values and "样本品牌" in values
    assert "SBR" not in values  # remote_search: false
    assert "手续费" not in values  # 增强词不单独检索
    assert plan.brand_tokens == ("sbr", "samplebrand", "orbitbank")
    assert plan.domains == ("sbr.int",)
    assert plan.project_ids == ("sample-brand-protection",)


def test_query_plan_never_includes_executives(tmp_path: Path) -> None:
    rules = ProjectRules.model_validate(
        {
            "project": "p",
            "authorization_ref": "A",
            "sets": {
                "brand": {"terms": ["Brand Name"]},
                "executives": {
                    "type": "executive",
                    "approval_ref": "DPO-1",
                    "terms": ["Jane Doe"],
                },
            },
            "domains": {"official": ["x.int"], "brand_tokens": ["x"]},
        }
    )
    assert {t.value for t in build_query_plan(rules).terms} == {"Brand Name"}


async def test_echo_connector(sbr_rules: ProjectRules) -> None:
    ctx = make_context(sbr_rules, connector_id="echo")
    conn = EchoConnector(ctx, {"items": [{"a": 1}, {"a": 2}], "delay": 0})
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert [i.payload for i in items] == [{"a": 1}, {"a": 2}]
    assert items[0].project_ids == ("sample-brand-protection",)
