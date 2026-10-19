from opti.configs import kinds
from opti.configs.runtime import ConfigRuntime
from opti.configs.testing import override
from opti.core.config import ProjectRules
from opti.sharing import SharingConfig


def test_sharing_kind_and_problems(sbr_rules: ProjectRules) -> None:
    config = SharingConfig.model_validate(
        {
            "siem": {
                "webhook": {"enabled": True, "url": "https://s.example", "format": "splunk_hec"}
            },
        }
    )
    spec = kinds.kind("sharing")
    assert spec.problems is not None
    assert spec.problems(config, {}) == ["SIEM Webhook（splunk_hec）需要令牌"]
    assert spec.problems(config, {"siem_webhook_token": "t"}) == []
    runtime = ConfigRuntime.static(sbr_rules)
    override(runtime, sharing=config)
    assert runtime.snapshot.sharing.siem.webhook.format == "splunk_hec"
