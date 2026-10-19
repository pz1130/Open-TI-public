import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from opti.alerting.config import AlertingConfig, load_alerting_config
from opti.alerting.dispatcher import AlertDispatcher, Route, build_routes
from opti.alerting.email import build_alert_email, build_notice_email, build_report_email
from opti.alerting.teams import (
    TeamsSink,
    build_card,
    build_notice_card,
    build_report_card,
)
from opti.alerting.views import AlertView, Notice, defang
from opti.core.reports import ReportView, empty_content, report_view
from opti.sdk.http import RateLimitedHttpClient
from opti.sdk.testing import make_http

T = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
VIEW = AlertView(
    alert_id=7, project_id="sample-brand-protection", severity="critical", category="phishing_site",
    domain="sbr-loans.com", score=93, reasons=("brand_label", "fraud_affix"), first_seen=T,
    created_at=T, link="https://ti.example/alerts/7",
)  # fmt: skip


def test_defang() -> None:
    assert defang("www.sbr-loans.com") == "www[.]sbr-loans[.]com"


def test_card_is_defanged_and_links_back() -> None:
    text = json.dumps(build_card(VIEW), ensure_ascii=False)
    assert "sbr-loans[.]com" in text and "sbr-loans.com" not in text
    assert "严重" in text and "钓鱼网站" in text and "https://ti.example/alerts/7" in text
    card = build_card(VIEW)
    assert card["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"


def test_impersonation_account_has_a_readable_label() -> None:
    view = AlertView(
        alert_id=8, project_id="sample-brand-protection", severity="high",
        category="impersonation_account", domain="https://bsky.app/profile/did:plc:bad",
        score=68, reasons=("display_same", "avatar"), first_seen=T, created_at=T,
        link="https://ti.example/alerts/8",
    )  # fmt: skip
    text = json.dumps(build_card(view), ensure_ascii=False)
    assert "冒充社交账号" in text and "impersonation_account" not in text


def test_emails() -> None:
    cfg = AlertingConfig.model_validate(
        {"email": {"enabled": True, "sender": "ti@x.example", "recipients": ["soc@x.example"]}}
    )
    msg = build_alert_email(VIEW, cfg.smtp, ("soc@example.org",))
    assert msg["Subject"].startswith("[严重]") and msg["To"] == "soc@example.org"
    body = msg.get_content()
    assert "sbr-loans[.]com" in body and "sbr-loans.com" not in body


def test_load_config(tmp_path: Path) -> None:
    assert load_alerting_config(tmp_path / "missing.yaml") == AlertingConfig()
    p = tmp_path / "a.yaml"
    p.write_text("public_base_url: https://ti.example\nimmediate: [critical]\n", encoding="utf-8")
    cfg = load_alerting_config(p)
    assert cfg.public_base_url == "https://ti.example" and cfg.channels == ()


async def test_teams_sink_posts() -> None:
    posted: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        return httpx.Response(202)

    await TeamsSink(make_http(handler), "https://hook.example/x").send_alert(VIEW)
    assert posted and posted[0]["type"] == "message"


WEBHOOK = "https://hook.example/secret-token-do-not-log"


async def test_failed_post_does_not_log_webhook(caplog: pytest.LogCaptureFixture) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    route = Route.default(TeamsSink(make_http(handler), WEBHOOK))
    dispatcher = AlertDispatcher(AlertingConfig(), [route])
    with caplog.at_level(logging.WARNING, logger="opti.alerting"):
        ok = await dispatcher._send(route, lambda sink: sink.send_alert(VIEW))
    assert ok is False
    assert WEBHOOK not in caplog.text
    assert "HttpError" in caplog.text and "500" in caplog.text


def test_build_routes_marks_missing_webhook_unavailable() -> None:
    cfg = AlertingConfig.model_validate({"teams": {"enabled": True}})
    http = RateLimitedHttpClient()
    [route] = build_routes(cfg, http, {})
    assert route.id == "teams" and route.sink is None and route.problem == "未设置 Webhook 地址"
    [route] = build_routes(cfg, http, {"channel:teams:webhook_url": "http://plain"})
    assert route.sink is None
    [route] = build_routes(cfg, http, {"channel:teams:webhook_url": "https://hook.example/x"})
    assert route.sink is not None and route.sink.name == "teams"


NOTICE = Notice(
    title="下架投诉 #3 超过 SLA 未处理",
    facts=(("投诉对象", "Cheap Registrar LLC"), ("域名", "sbr-loans[.]com")),
    link="https://ti.example/takedowns?id=3",
)


def test_notice_card_and_email() -> None:
    card = json.dumps(build_notice_card(NOTICE), ensure_ascii=False)
    assert "下架投诉 #3 超过 SLA 未处理" in card and "Cheap Registrar LLC" in card
    assert "https://ti.example/takedowns?id=3" in card
    msg = build_notice_email(NOTICE, AlertingConfig().smtp, ("soc@example.org",))
    assert msg["Subject"] == NOTICE.title and "域名：sbr-loans[.]com" in msg.get_content()


class _NoticeSink:
    def __init__(self, name: str, fail: bool) -> None:
        self.name = name
        self.fail = fail
        self.notices: list[Notice] = []

    async def send_alert(self, view: AlertView) -> None: ...

    async def send_report(self, report: ReportView) -> None: ...

    async def send_notice(self, notice: Notice) -> None:
        if self.fail:
            raise RuntimeError("down")
        self.notices.append(notice)


async def test_dispatcher_send_notice() -> None:
    ok, bad = _NoticeSink("ok", False), _NoticeSink("bad", True)
    assert (
        await AlertDispatcher(
            AlertingConfig(), [Route.default(bad), Route.default(ok)]
        ).send_notice(NOTICE)
        is True
    )
    assert ok.notices == [NOTICE]
    assert (
        await AlertDispatcher(AlertingConfig(), [Route.default(bad)]).send_notice(NOTICE) is False
    )
    assert await AlertDispatcher(AlertingConfig(), []).send_notice(NOTICE) is True


REPORT = report_view(
    5,
    {
        **empty_content("daily", start=T - timedelta(days=1), end=T),
        "alerts": [
            {
                "alert_id": 7,
                "severity": "medium",
                "category": "typosquat_domain",
                "subject": "sbr-loans.com",
                "score": 50,
            }
        ],
    },
    "https://ti.example",
)


def test_report_card_and_email() -> None:
    text = json.dumps(build_report_card(REPORT), ensure_ascii=False)
    assert "威胁情报日报 2026-10-02" in text and "sbr-loans[.]com" in text
    assert "sbr-loans.com" not in text and "https://ti.example/reports/5" in text
    assert len(text.encode()) < 20_000
    cfg = AlertingConfig.model_validate(
        {"email": {"enabled": True, "sender": "ti@x.example", "recipients": ["soc@x.example"]}}
    )
    msg = build_report_email(REPORT, cfg.smtp, ("soc@example.org",))
    assert msg["Subject"] == "威胁情报日报 2026-10-02" and msg.is_multipart()
    html_part = msg.get_body(preferencelist=("html",))
    text_part = msg.get_body(preferencelist=("plain",))
    assert html_part is not None and "<h1>" in html_part.get_content()
    assert text_part is not None and "https://ti.example/alerts/7" in text_part.get_content()
