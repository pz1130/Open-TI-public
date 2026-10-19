"""告警分发器随项目与告警配置重建；工单客户端随通知配置（含密钥）重建。"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from opti.alerting.dispatcher import AlertDispatcher
from opti.alerting.views import AlertView
from opti.configs.runtime import ConfigSnapshot
from opti.sdk.http import RateLimitedHttpClient
from opti.tickets.client import PushResult, TicketClient, build_ticket_client

# ConfigSnapshot.of 的 alerting_digest 不含密钥；运行时 digest 含密钥戳。两边都要比。
_Key = tuple[str, tuple[tuple[str, str | None], ...]]


def _alerting_key(snapshot: ConfigSnapshot) -> _Key:
    return f"{snapshot.rules.project}:{snapshot.alerting_digest}", tuple(
        sorted(snapshot.alerting_secrets.items())
    )


class DispatcherCache:
    def __init__(self, build: Callable[[ConfigSnapshot], AlertDispatcher]) -> None:
        self._build = build
        self._key: _Key | None = None
        self._current: AlertDispatcher | None = None

    def get(self, snapshot: ConfigSnapshot) -> AlertDispatcher:
        key = _alerting_key(snapshot)
        if self._current is None or key != self._key:
            self._current = self._build(snapshot)
            self._key = key
        return self._current


class TicketUnavailable(RuntimeError):
    pass


class ConfigBoundTickets:
    """工单客户端：邮件方式依赖告警配置中的 SMTP 与密钥，配置变化后下一次推送前重建。"""

    def __init__(
        self,
        snapshot: Callable[[], ConfigSnapshot],
        build: Callable[[ConfigSnapshot], TicketClient | None],
    ) -> None:
        self._snapshot = snapshot
        self._build = build
        self._key: _Key | None = None
        self._client: TicketClient | None = None

    def current(self) -> TicketClient | None:
        snap = self._snapshot()
        key = (
            snap.digest("alerting", "tickets"),
            tuple(sorted({**snap.secrets("alerting"), **snap.secrets("tickets")}.items())),
        )
        if key != self._key:
            self._client = self._build(snap)
            self._key = key
        return self._client

    @property
    def name(self) -> str:
        client = self.current()
        return client.name if client is not None else "unavailable"

    async def push(
        self,
        view: AlertView,
        extra: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
        existing_ref: str | None = None,
    ) -> PushResult:
        client = self.current()
        if client is None:
            raise TicketUnavailable("工单客户端不可用：检查工单与 SMTP 配置")
        return await client.push(
            view, extra, idempotency_key=idempotency_key, existing_ref=existing_ref
        )


def active_ticket_client(tickets: TicketClient | None) -> TicketClient | None:
    """调用方用 is None 跳过未配置的工单。绑定客户端在当前快照建不出来时同样视为未配置。"""
    if isinstance(tickets, ConfigBoundTickets):
        return tickets.current()
    return tickets


def ticket_source(
    snapshot: Callable[[], ConfigSnapshot], http: RateLimitedHttpClient
) -> ConfigBoundTickets:
    def build(snap: ConfigSnapshot) -> TicketClient | None:
        ticket_secrets = snap.secrets("tickets")
        smtp_secrets = snap.secrets("alerting")
        return build_ticket_client(
            snap.tickets,
            snap.alerting,
            http,
            webhook_url=ticket_secrets.get("webhook_url"),
            signing_key=ticket_secrets.get("signing_key"),
            smtp_auth=(smtp_secrets.get("smtp_username"), smtp_secrets.get("smtp_password")),
            secrets=ticket_secrets,
        )

    return ConfigBoundTickets(snapshot, build)
