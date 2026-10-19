import logging

import httpx
import pytest

from opti.connectors.phishtank.connector import DATA_URL, PhishtankConnector
from opti.core.config import ProjectRules
from opti.sdk.context import EnvSecretProvider
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

KEY = "p" * 64
DATA = [
    {"phish_id": 9, "url": "https://sbr-loans.com/verify", "verified": "yes", "online": "yes",
     "target": "Other", "submission_time": "2026-10-02T06:00:00+00:00"},
    {"phish_id": 10, "url": "https://evil.top/sbr/login", "verified": "no", "online": "yes", "target": "Other"},
    {"phish_id": 11, "url": "https://bank.example/login", "verified": "yes", "online": "yes"},
]  # fmt: skip


def _connector(rules: ProjectRules, handler) -> PhishtankConnector:  # type: ignore[no-untyped-def]
    secrets = EnvSecretProvider({"OPTI_SECRET_PHISHTANK_APP_KEY": KEY})
    return PhishtankConnector(
        make_context(rules, connector_id="phishtank", handler=handler, secrets=secrets), {}
    )


async def test_online_valid(sbr_rules: ProjectRules) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == DATA_URL.format(key=KEY)
        return httpx.Response(200, json=DATA)

    items = [i async for i in _connector(sbr_rules, handler).fetch(build_query_plan(sbr_rules))]
    assert [(i.payload["feed_url"], i.payload["intel"]["confirmed"]) for i in items] == [
        ("https://sbr-loans.com/verify", True),
        ("https://evil.top/sbr/login", False),
    ]
    assert items[0].payload["intel"]["phish_id"] == 9


async def test_phishtank_key_not_leaked(
    sbr_rules: ProjectRules, caplog: pytest.LogCaptureFixture
) -> None:
    """Key 在 URL 路径里：下载失败不能抛出带 URL 的异常（会写进 connector_run.message），日志要脱敏。"""
    with caplog.at_level(logging.INFO):
        items = [
            i
            async for i in _connector(sbr_rules, lambda _r: httpx.Response(500)).fetch(
                build_query_plan(sbr_rules)
            )
        ]
    assert items == []
    assert KEY not in caplog.text and "PhishTank" in caplog.text


async def test_phishtank_success_request_log_is_redacted(
    sbr_rules: ProjectRules, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        items = [
            i
            async for i in _connector(sbr_rules, lambda _r: httpx.Response(200, json=DATA)).fetch(
                build_query_plan(sbr_rules)
            )
        ]
    assert len(items) == 2
    assert KEY not in caplog.text
    assert "HTTP Request" in caplog.text and "****pppp" in caplog.text
