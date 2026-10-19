"""按配置建 Jira / ServiceNow 客户端，生成工单跳转地址（设计 2026-10-16）。"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from urllib.parse import quote

from opti.tickets.config import TicketsConfig
from opti.tickets.jira import ISSUE_KEY, JiraTicketClient
from opti.tickets.remote import HttpFactory
from opti.tickets.servicenow import ServiceNowTicketClient

log = logging.getLogger("opti.tickets")
RemoteClient = JiraTicketClient | ServiceNowTicketClient


def build_remote_client(
    cfg: TicketsConfig, secrets: Mapping[str, str | None], factory: HttpFactory
) -> RemoteClient | None:
    """不看 cfg.enabled：测试连接在启用前也能用。缺密钥时返回 None。"""
    if cfg.mode == "jira" and cfg.jira is not None:
        token = secrets.get("jira_api_token")
        if not token:
            log.warning("工单方式为 Jira，但未设置 API Token")
            return None
        return JiraTicketClient(
            cfg.jira, token, include_accounts=cfg.include_accounts, http_factory=factory
        )
    if cfg.mode == "servicenow" and cfg.servicenow is not None:
        sn = cfg.servicenow
        name = "servicenow_password" if sn.auth == "basic" else "servicenow_client_secret"
        secret = secrets.get(name)
        if not secret:
            log.warning("工单方式为 ServiceNow，但未设置 %s", name)
            return None
        return ServiceNowTicketClient(
            sn, secret=secret, include_accounts=cfg.include_accounts, http_factory=factory
        )
    return None


def ticket_url(cfg: TicketsConfig, ref: str | None) -> str | None:
    """工单编号的跳转地址：只有 Jira / ServiceNow 方式能生成。"""
    if not ref:
        return None
    if cfg.mode == "jira" and cfg.jira is not None:
        if not ISSUE_KEY.fullmatch(ref):
            return None
        return f"{cfg.jira.base_url}/browse/{quote(ref, safe='')}"
    if cfg.mode == "servicenow" and cfg.servicenow is not None:
        sn = cfg.servicenow
        target = quote(f"{sn.table}.do?sysparm_query=number={ref}", safe="")
        return f"{sn.base_url}/nav_to.do?uri={target}"
    return None
