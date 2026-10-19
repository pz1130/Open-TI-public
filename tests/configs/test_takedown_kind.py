from pathlib import Path

from opti.configs import kinds
from opti.configs.runtime import ConfigRuntime
from opti.configs.testing import override
from opti.core.config import ProjectRules
from opti.settings import Settings
from opti.takedown.config import TakedownConfig

REPO = Path(__file__).resolve().parents[2]


def test_takedown_kind_reads_platforms_file() -> None:
    settings = Settings(takedown_config=REPO / "config" / "takedown" / "platforms.yaml")
    cfg = kinds.parse("takedown", kinds.read_file("takedown", settings), allow_aliases=True)
    assert isinstance(cfg, TakedownConfig)
    assert cfg.platform_for("www.linkedin.com") is not None
    text = kinds.from_data("takedown", kinds.to_data("takedown", cfg))
    assert kinds.parse("takedown", text) == cfg


def test_no_visit_follows_snapshot(sbr_rules: ProjectRules) -> None:
    rt = ConfigRuntime.static(sbr_rules)
    assert rt.snapshot.takedown.platform_for("t.me") is None
    override(
        rt,
        takedown=TakedownConfig.model_validate(
            {"platforms": [{"id": "telegram", "name": "Telegram", "hosts": ["t.me"]}]}
        ),
    )
    assert rt.snapshot.takedown.platform_for("t.me") is not None
    override(rt, secrets={"alerting": {"smtp_password": "x"}})
    assert rt.snapshot.alerting_secrets == {"smtp_password": "x"}
