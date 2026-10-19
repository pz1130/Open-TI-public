from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from opti.connectors.github_code.connector import GithubCodeConnector
from opti.core.config import ProjectRules
from opti.sdk.base import MissingCredential
from opti.sdk.context import EnvSecretProvider
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context

SECRETS = EnvSecretProvider({"OPTI_SECRET_GITHUB_CODE_TOKEN": "t" * 40})
FAKE_AWS = "AKIA" + "QYLPMN5HTWX2BVFC"


def _item(repo: str, path: str, sha: str, *, private: bool = False, fork: bool = False,
          fragment: str = "") -> dict[str, Any]:  # fmt: skip
    return {
        "name": path.rsplit("/", 1)[-1], "path": path, "sha": sha,
        "html_url": f"https://github.com/{repo}/blob/main/{path}",
        "repository": {"full_name": repo, "private": private, "fork": fork,
                       "owner": {"login": repo.split("/")[0]}},
        "text_matches": [{"fragment": fragment}] if fragment else [],
    }  # fmt: skip


async def _run(
    rules: ProjectRules, pages: dict[str, list[dict[str, Any]]], **config: Any
) -> tuple[list[Any], list[str]]:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer " + "t" * 40
        assert "text-match" in request.headers["accept"]
        query = parse_qs(urlsplit(str(request.url)).query)["q"][0]
        seen.append(query)
        return httpx.Response(200, json={"items": pages.get(query, [])})

    context = make_context(rules, connector_id="github_code", handler=handler, secrets=SECRETS)
    connector = GithubCodeConnector(context, config)
    connector.validate_config()
    return [item async for item in connector.fetch(build_query_plan(rules))], seen


async def test_terms_and_payload(sbr_rules: ProjectRules) -> None:
    domain = sbr_rules.domains.official[0]
    pages = {
        f'"{domain}"': [_item("dev1/tools", "README.md", "s1", fragment=f"see https://www.{domain}")],
        '"intranet-gw01"': [_item("dev2/deploy", "config/app.env", "s2", fork=True,
                                fragment=f"HOST=intranet-gw01\nAWS={FAKE_AWS}")],
    }  # fmt: skip
    items, seen = await _run(sbr_rules, pages, internal_terms=["intranet-gw01"])
    assert seen == [f'"{domain}"', '"intranet-gw01"']
    hits = {item.payload["code_hit"]["repo"]: item.payload["code_hit"] for item in items}
    assert hits["dev1/tools"]["term_kind"] == "domain"
    deploy = hits["dev2/deploy"]
    assert (
        deploy["term_kind"] == "internal" and deploy["fork"] and deploy["path"] == "config/app.env"
    )
    assert "AKIA…[REDACTED:" in deploy["fragments"][0] and FAKE_AWS[4:] not in str(deploy)
    assert items[1].source_item_id == "dev2/deploy:config/app.env:s2"


async def test_excludes_own_owners_and_private(sbr_rules: ProjectRules) -> None:
    domain = sbr_rules.domains.official[0]
    pages = {f'"{domain}"': [
        _item("OurOrg/website", "index.html", "a1"),
        _item("someone/private-repo", "x.cfg", "a2", private=True),
        _item("bad name/../x", "x", "a3"),
        _item("dev1/tools", "README.md", "a4"),
        _item("dev1/tools", "README.md", "a4"),
    ]}  # fmt: skip
    items, _ = await _run(sbr_rules, pages, exclude_owners=["ourorg"])
    assert [item.payload["code_hit"]["repo"] for item in items] == ["dev1/tools"]


async def test_query_budget_and_errors(sbr_rules: ProjectRules) -> None:
    items, seen = await _run(
        sbr_rules, {}, internal_terms=[f"term{i}" for i in range(20)], max_queries=3
    )
    assert len(seen) == 3 and items == []
    context = make_context(sbr_rules, connector_id="github_code",
                           handler=lambda _r: httpx.Response(403, json={}), secrets=SECRETS)  # fmt: skip
    assert [
        item async for item in GithubCodeConnector(context, {}).fetch(build_query_plan(sbr_rules))
    ] == []
    with pytest.raises(MissingCredential):
        GithubCodeConnector(
            make_context(sbr_rules, connector_id="github_code"), {}
        ).validate_config()
    with pytest.raises(ValueError, match="官方公开代码 API"):
        GithubCodeConnector(context, {"api_base": "https://evil.example"}).validate_config()
