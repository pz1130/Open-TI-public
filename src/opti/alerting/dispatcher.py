"""告警分发：按渠道过滤推送；失败或不可用的渠道可重试。

渠道连不上或出错（超时、网络错误、5xx、429、SMTP 临时错误）后进入退避（5、10、20、30 分钟，封顶 30 分钟），
退避期内告警、报告与运营提醒都跳过它，成功一次即复位。服务器明确拒收某一条消息（其他 4xx、SMTP 5xx）
只算这条失败，不让渠道退避，避免一条发不出去的告警堵住后面的告警。
退避状态只在本进程内，worker 重启或告警配置变更（分发器重建）后清零。
"""

from __future__ import annotations

import logging
import smtplib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import select, true
from sqlalchemy.ext.asyncio import AsyncSession

from opti.alerting.config import ALL_REPORTS, AlertingConfig, Channel, webhook_secret
from opti.alerting.email import EmailSink, SendFn, smtp_sender
from opti.alerting.teams import TeamsSink
from opti.alerting.views import AlertView, Notice, load_views
from opti.core import policy
from opti.core.reports import ReportView, report_view
from opti.core.scoring import Severity
from opti.db.models import Alert, Report
from opti.sdk.http import HttpError, RateLimitedHttpClient

log = logging.getLogger("opti.alerting")


def _channel_down(e: Exception) -> bool:
    """渠道级故障才退避；服务器已应答并明确拒收这一条时不算。"""
    if isinstance(e, HttpError) and e.status is not None:
        return not (400 <= e.status < 500 and e.status not in (408, 429))
    if isinstance(e, smtplib.SMTPResponseException):
        return e.smtp_code < 500
    return True


class Sink(Protocol):
    name: str  # 渠道名，记录在 alert.notified_sinks / report.sent_sinks 中

    async def send_alert(self, view: AlertView) -> None: ...

    async def send_report(self, report: ReportView) -> None: ...

    async def send_notice(self, notice: Notice) -> None: ...


@dataclass(frozen=True)
class Route:
    """一个渠道及其 sink；sink 为 None 表示渠道不可用（缺 Webhook、密钥无法解密等），problem 写原因。"""

    channel: Channel
    sink: Sink | None
    problem: str | None = None

    @property
    def id(self) -> str:
        return self.channel.id

    @classmethod
    def default(cls, sink: Sink) -> Route:
        """测试与命令行直接注入的 sink：沿用升级前的默认规则（严重、高危立即推送，接收全部报告与提醒）。"""
        channel = Channel(
            id=sink.name,
            name=sink.name,
            type="teams",
            severities=(Severity.CRITICAL, Severity.HIGH),
            reports=ALL_REPORTS,
            notices=True,
        )
        return cls(channel, sink)


def build_routes(
    cfg: AlertingConfig,
    http: RateLimitedHttpClient,
    secrets: Mapping[str, str | None],
    *,
    send_factory: Callable[..., SendFn] = smtp_sender,
) -> list[Route]:
    routes: list[Route] = []
    smtp_send: SendFn | None = None
    for ch in cfg.channels:
        if not ch.enabled:
            continue
        if ch.type == "teams":
            url = secrets.get(webhook_secret(ch.id))
            if not url:
                routes.append(Route(ch, None, "未设置 Webhook 地址"))
            elif not url.startswith("https://"):
                routes.append(Route(ch, None, "Webhook 地址必须是 https"))
            else:
                routes.append(Route(ch, TeamsSink(http, url, name=ch.id)))
            continue
        if smtp_send is None:
            smtp_send = send_factory(
                cfg.smtp, secrets.get("smtp_username"), secrets.get("smtp_password")
            )
        routes.append(Route(ch, EmailSink(ch.id, cfg.smtp, ch.recipients, smtp_send)))
    for r in routes:
        if r.sink is None:
            log.warning("告警渠道 %s 不可用：%s", r.id, r.problem)
    return routes


class AlertDispatcher:
    def __init__(
        self,
        cfg: AlertingConfig,
        routes: Sequence[Route],
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        project_id: str | None = None,
    ) -> None:
        self._cfg = cfg
        self._routes = [r for r in routes if r.channel.enabled]
        self._clock = clock
        self._project_id = project_id
        self._failures: dict[str, int] = {}  # 渠道 ID → 连续失败次数
        self._retry_at: dict[str, datetime] = {}  # 渠道 ID → 退避结束时间
        if not any(r.sink is not None for r in self._routes):
            log.warning("没有可用的告警渠道：告警只会入库，不会推送")

    @property
    def routes(self) -> list[Route]:
        return list(self._routes)

    def _ready(self, route: Route) -> bool:
        """渠道可用且不在退避期内。"""
        if route.sink is None:
            return False
        retry_at = self._retry_at.get(route.id)
        return retry_at is None or self._clock() >= retry_at

    async def _send(self, route: Route, send: Callable[[Sink], Awaitable[None]]) -> bool:
        assert route.sink is not None
        try:
            await send(route.sink)
        except Exception as e:  # 不记录异常文本：HttpError 含 Webhook URL
            status = f"（{e.status}）" if isinstance(e, HttpError) else ""
            if not _channel_down(e):
                log.warning("告警渠道 %s 拒收了一条消息：%s%s", route.id, type(e).__name__, status)
                return False
            failures = self._failures.get(route.id, 0) + 1
            self._failures[route.id] = failures
            backoff = policy.current().delivery.backoff_minutes
            wait = timedelta(minutes=backoff[min(failures, len(backoff)) - 1])
            self._retry_at[route.id] = self._clock() + wait
            log.warning(
                "告警渠道 %s 发送失败：%s%s；%d 分钟后重试",
                route.id, type(e).__name__, status, wait // timedelta(minutes=1),
            )  # fmt: skip
            return False
        self._failures.pop(route.id, None)
        self._retry_at.pop(route.id, None)
        return True

    async def _deliver(
        self,
        targets: Sequence[Route],
        delivered: Sequence[str],
        send: Callable[[Sink], Awaitable[None]],
    ) -> list[str]:
        out = list(delivered)
        for r in targets:
            if r.id in out or not self._ready(r):  # 不可用或退避中的渠道本轮记为失败
                continue
            if await self._send(r, send):
                out.append(r.id)
        return out

    async def dispatch_pending(self, session: AsyncSession) -> int:
        """按渠道过滤推送；目标为空记完成，目标渠道不可用或失败时保留待推送，只补发未送达的渠道。"""
        severities = sorted({s.value for r in self._routes for s in r.channel.severities})
        if not severities:
            return 0
        alerts = (
            await session.scalars(
                select(Alert)
                .where(
                    Alert.status.in_(("open", "acknowledged")),
                    Alert.project_id == self._project_id
                    if self._project_id is not None
                    else true(),
                    Alert.notified_at.is_(None),
                    Alert.ignored_at.is_(None),
                    Alert.created_at
                    >= self._clock() - timedelta(days=policy.current().delivery.alert_window_days),
                    Alert.severity.in_(severities),
                )
                .order_by(Alert.id)
                .with_for_update(skip_locked=True)
            )
        ).all()
        by_id = {a.id: a for a in alerts}
        sent = 0
        for view in await load_views(session, list(by_id), self._cfg.public_base_url):
            alert = by_id[view.alert_id]
            targets = [r for r in self._routes if r.channel.matches(view.severity, view.category)]

            def send_alert(sink: Sink, v: AlertView = view) -> Awaitable[None]:
                return sink.send_alert(v)

            delivered = await self._deliver(targets, alert.notified_sinks, send_alert)
            alert.notified_sinks = delivered
            if all(r.id in delivered for r in targets):
                alert.notified_at = self._clock()
                sent += bool(targets)
        await session.flush()
        return sent

    async def send_reports(self, session: AsyncSession) -> int:
        """近七日的报告发给接收该类型的渠道；目标为空直接记已发送。"""
        rows = (
            await session.scalars(
                select(Report)
                .where(
                    Report.sent_at.is_(None),
                    Report.project_id == self._project_id
                    if self._project_id is not None
                    else true(),
                    Report.created_at
                    >= self._clock() - timedelta(days=policy.current().delivery.report_retry_days),
                )
                .order_by(Report.id)
                .with_for_update(skip_locked=True)
            )
        ).all()
        done = 0
        for row in rows:
            view = report_view(row.id, row.content, self._cfg.public_base_url)
            targets = [r for r in self._routes if row.kind in r.channel.reports]

            def send_report(sink: Sink, v: ReportView = view) -> Awaitable[None]:
                return sink.send_report(v)

            delivered = await self._deliver(targets, row.sent_sinks, send_report)
            row.sent_sinks = delivered
            if all(r.id in delivered for r in targets):
                row.sent_at = self._clock()
                done += 1
        await session.flush()
        return done

    async def send_notice(self, notice: Notice) -> bool:
        """运营提醒：发给接收提醒的渠道，至少一个成功即送达；无人接收时视为送达，避免无限重试。"""
        targets = [r for r in self._routes if r.channel.notices]
        if not targets:
            return True
        delivered = False
        for r in targets:
            if self._ready(r):
                delivered |= await self._send(r, lambda sink: sink.send_notice(notice))
        return delivered
