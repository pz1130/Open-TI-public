import pytest
from pydantic import ValidationError

from opti.configs.kinds import REGISTRY
from opti.tickets.config import JiraConfig, ServiceNowConfig, TicketsConfig

JIRA = {"base_url": "https://acme.atlassian.net/", "email": "ti@acme.org", "project_key": "SEC"}
SN = {"base_url": "https://acme.service-now.com", "username": "opti"}


def test_old_config_still_loads() -> None:
    cfg = TicketsConfig.model_validate({"enabled": True, "mode": "webhook", "auto_push": ["high"]})
    assert cfg.jira is None and cfg.servicenow is None
    assert cfg.include_accounts is False and cfg.proxy is None


def test_jira_section() -> None:
    cfg = TicketsConfig.model_validate(
        {"enabled": True, "mode": "jira", "jira": {**JIRA, "priority_map": {"critical": "Highest"},
                                                    "extra_fields": {"labels": ["drp"], "customfield_10050": {"value": "Brand"}}}}
    )  # fmt: skip
    assert cfg.jira is not None
    assert cfg.jira.base_url == "https://acme.atlassian.net"  # 去掉末尾斜杠
    assert cfg.jira.issue_type == "Task"
    assert cfg.jira.priority_map == {"critical": "Highest"}


@pytest.mark.parametrize(
    "base_url",
    ["http://acme.atlassian.net", "https://acme.example.com", "https://acme.atlassian.net/jira",
     "https://acme.atlassian.net:8443", "https://u:p@acme.atlassian.net"],
)  # fmt: skip
def test_jira_base_url_must_be_cloud(base_url: str) -> None:
    with pytest.raises(ValidationError):
        JiraConfig.model_validate({**JIRA, "base_url": base_url})


@pytest.mark.parametrize("field", ["project", "issuetype", "summary", "description", "priority"])
def test_jira_extra_fields_cannot_override_platform_fields(field: str) -> None:
    with pytest.raises(ValidationError, match=field):
        JiraConfig.model_validate({**JIRA, "extra_fields": {field: "x"}})


def test_jira_project_key_and_extra_field_names() -> None:
    for bad in ("sec", "S", "SEC-1"):
        with pytest.raises(ValidationError):
            JiraConfig.model_validate({**JIRA, "project_key": bad})
    with pytest.raises(ValidationError):
        JiraConfig.model_validate({**JIRA, "extra_fields": {"bad key": 1}})
    with pytest.raises(ValidationError):
        JiraConfig.model_validate({**JIRA, "extra_fields": {f"f{i}": i for i in range(31)}})
    with pytest.raises(ValidationError):
        JiraConfig.model_validate({**JIRA, "priority_map": {"high": " "}})
    for labels in ("drp", [1], [""]):
        with pytest.raises(ValidationError, match="labels"):
            JiraConfig.model_validate({**JIRA, "extra_fields": {"labels": labels}})


def test_servicenow_section() -> None:
    sn = ServiceNowConfig.model_validate(
        {**SN, "table": "sn_si_incident", "urgency_impact_map": {"critical": {"urgency": 1, "impact": 1}},
         "extra_fields": {"assignment_group": "Security Operations"}}
    )  # fmt: skip
    assert sn.auth == "basic" and sn.table == "sn_si_incident"
    assert sn.urgency_impact_map["critical"].urgency == 1  # type: ignore[index]
    with pytest.raises(ValidationError):
        ServiceNowConfig.model_validate({"base_url": SN["base_url"]})  # basic 缺用户名
    with pytest.raises(ValidationError):
        ServiceNowConfig.model_validate({"base_url": SN["base_url"], "auth": "oauth"})
    assert (
        ServiceNowConfig.model_validate(
            {"base_url": SN["base_url"], "auth": "oauth", "client_id": "abc"}
        ).client_id
        == "abc"
    )
    for bad in (
        {"table": "Incident"},
        {"table": "incident;drop"},
        {"base_url": "http://acme.service-now.com"},
        {"urgency_impact_map": {"high": {"urgency": 4, "impact": 1}}},
        {"extra_fields": {"correlation_id": "x"}},
        {"extra_fields": {"work_notes": "x"}},
    ):
        with pytest.raises(ValidationError):
            ServiceNowConfig.model_validate({**SN, **bad})


def test_mode_requires_its_section_and_keeps_the_other() -> None:
    with pytest.raises(ValidationError):
        TicketsConfig.model_validate({"mode": "jira"})
    with pytest.raises(ValidationError):
        TicketsConfig.model_validate({"mode": "servicenow", "jira": JIRA})
    cfg = TicketsConfig.model_validate({"mode": "servicenow", "servicenow": SN, "jira": JIRA})
    assert cfg.jira is not None  # 切换方式时另一段保留


def test_proxy() -> None:
    assert TicketsConfig(proxy="http://proxy.internal:3128").proxy == "http://proxy.internal:3128"
    assert TicketsConfig(proxy="  ").proxy is None
    with pytest.raises(ValidationError):
        TicketsConfig(proxy="socks5://proxy:1080")


def test_ticket_secret_names_and_env_fallback() -> None:
    kind = REGISTRY["tickets"]
    assert kind.secret_names is not None
    assert kind.secret_names(TicketsConfig()) == {
        "webhook_url", "signing_key", "jira_api_token", "servicenow_password", "servicenow_client_secret",
    }  # fmt: skip
    assert kind.env_fallback["jira_api_token"] == "OPTI_SECRET_TICKETS_JIRA_API_TOKEN"
    assert kind.env_fallback["servicenow_client_secret"] == (
        "OPTI_SECRET_TICKETS_SERVICENOW_CLIENT_SECRET"
    )
