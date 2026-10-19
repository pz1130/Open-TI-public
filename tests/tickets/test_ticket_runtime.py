import pytest
from pydantic import ValidationError

from opti.alerting.runtime import ticket_source
from opti.configs.runtime import ConfigRuntime
from opti.configs.testing import override
from opti.core.config import ProjectRules
from opti.sdk.http import RateLimitedHttpClient
from opti.tickets.client import WebhookTicketClient
from opti.tickets.config import TicketsConfig


async def test_ticket_client_rebuilds_on_secret_change(sbr_rules: ProjectRules) -> None:
    runtime = ConfigRuntime.static(sbr_rules)
    http = RateLimitedHttpClient()
    source = ticket_source(lambda: runtime.snapshot, http)
    assert source.current() is None
    override(
        runtime,
        tickets=TicketsConfig(enabled=True),
        secrets={
            "tickets": {
                "webhook_url": "https://a.example/t",
                "signing_key": "k" * 32,
            }
        },
    )
    first = source.current()
    assert isinstance(first, WebhookTicketClient)
    override(
        runtime,
        secrets={
            "tickets": {
                "webhook_url": "https://b.example/t",
                "signing_key": "k" * 32,
            }
        },
    )
    assert source.current() is not first
    override(runtime, tickets=TicketsConfig(enabled=False))
    assert source.current() is None
    await http.aclose()


def test_status_map_validation() -> None:
    with pytest.raises(ValidationError):
        TicketsConfig(status_map={" ": "closed"})
    with pytest.raises(ValidationError):
        TicketsConfig(status_map={f"s{i}": "closed" for i in range(51)})


async def test_ticket_source_builds_jira_client(sbr_rules: ProjectRules) -> None:
    from opti.tickets.jira import JiraTicketClient

    runtime = ConfigRuntime.static(sbr_rules)
    http = RateLimitedHttpClient()
    source = ticket_source(lambda: runtime.snapshot, http)
    jira = {"base_url": "https://acme.atlassian.net", "email": "ti@acme.org", "project_key": "SEC"}
    override(
        runtime,
        tickets=TicketsConfig.model_validate({"enabled": True, "mode": "jira", "jira": jira}),
    )
    assert source.current() is None  # 未设置 API Token
    override(runtime, secrets={"tickets": {"jira_api_token": "t"}})
    assert isinstance(source.current(), JiraTicketClient)
    await http.aclose()
