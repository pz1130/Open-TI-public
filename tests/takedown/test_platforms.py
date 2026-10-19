from pathlib import Path

import pytest
from pydantic import ValidationError

from opti.takedown.config import Platform, TakedownConfig, load_takedown_config

REPO = Path(__file__).resolve().parents[2]
LINKEDIN = Platform(id="linkedin", name="LinkedIn", hosts=("linkedin.com", "lnkd.in"))


def test_platform_hosts_match_by_label_boundary() -> None:
    cfg = TakedownConfig(platforms=(LINKEDIN,))
    assert cfg.platform_for("linkedin.com") == LINKEDIN
    assert cfg.platform_for("cn.linkedin.com.") == LINKEDIN
    assert cfg.platform_for("LNKD.IN") == LINKEDIN
    for host in ("linkedin.com.evil.top", "evil-linkedin.com", "notlinkedin.com", "", None):
        assert cfg.platform_for(host) is None


def test_platform_hosts_must_be_lowercase_domains() -> None:
    for bad in ("LinkedIn.com", "https://linkedin.com", "*.linkedin.com", "linkedin"):
        with pytest.raises(ValidationError):
            Platform(id="x", name="X", hosts=(bad,))
    with pytest.raises(ValidationError):
        Platform(id="x", name="X", hosts=())


def test_shipped_platform_list() -> None:
    cfg = load_takedown_config(REPO / "config" / "takedown" / "platforms.yaml")
    assert {platform.id for platform in cfg.platforms} == {
        "linkedin",
        "facebook",
        "instagram",
        "x",
        "telegram",
        "youtube",
        "tiktok",
        "wechat",
        "weibo",
        "bluesky",
        "mastodon",
    }
    assert cfg.platform_for("bsky.app").id == "bluesky"  # type: ignore[union-attr]
    assert cfg.platform_for("mastodon.social").id == "mastodon"  # type: ignore[union-attr]
    assert cfg.platform_for("t.me").channel.email == "abuse@telegram.org"  # type: ignore[union-attr]
    assert cfg.platform_for("mp.weixin.qq.com").id == "wechat"  # type: ignore[union-attr]
    assert cfg.platform_for("qq.com") is None
    assert cfg.sla_hours["platform"] == 72
