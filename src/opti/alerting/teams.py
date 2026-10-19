"""Microsoft Teams 推送：Workflows（Power Automate）Webhook + Adaptive Card（设计文档 13）。"""

from __future__ import annotations

from typing import Any

from opti.alerting.views import CATEGORY_LABEL, SEVERITY_LABEL, AlertView, Notice, defang
from opti.core.reports import ReportView
from opti.sdk.http import RateLimitedHttpClient


def _wrap(body: list[dict[str, Any]], actions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "actions": actions,
                },
            }
        ],
    }


def build_card(view: AlertView) -> dict[str, Any]:
    severity = SEVERITY_LABEL.get(view.severity, view.severity)
    category = CATEGORY_LABEL.get(view.category, view.category)
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": f"[{severity}] {category}",
            "weight": "Bolder",
            "size": "Medium",
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "域名", "value": defang(view.domain)},
                {"title": "评分", "value": str(view.score)},
                {"title": "命中原因", "value": "、".join(view.reasons) or "-"},
                {"title": "首次发现", "value": view.first_seen.isoformat()},
            ],
        },
    ]
    actions = [{"type": "Action.OpenUrl", "title": "在平台中查看", "url": view.link}]
    return _wrap(body, actions)


def build_report_card(report: ReportView) -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": report.title,
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
        },
        {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in report.facts]},
        *({"type": "TextBlock", "text": f"- {line}", "wrap": True} for line in report.lines),
    ]
    return _wrap(body, [{"type": "Action.OpenUrl", "title": "在平台中查看", "url": report.link}])


class TeamsSink:
    def __init__(
        self, http: RateLimitedHttpClient, webhook_url: str, *, name: str = "teams"
    ) -> None:
        self.name = name
        self._http = http
        self._url = webhook_url

    async def send_alert(self, view: AlertView) -> None:
        await self._http.post_json(self._url, build_card(view))

    async def send_report(self, report: ReportView) -> None:
        await self._http.post_json(self._url, build_report_card(report))

    async def send_notice(self, notice: Notice) -> None:
        await self._http.post_json(self._url, build_notice_card(notice))


def build_notice_card(notice: Notice) -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": notice.title,
            "weight": "Bolder",
            "size": "Medium",
            "wrap": True,
        },
        {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in notice.facts]},
    ]
    return _wrap(body, [{"type": "Action.OpenUrl", "title": "在平台中查看", "url": notice.link}])
