import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from opti.connectors.gitlab_projects.connector import GitLabProjectsConnector, _path, _project
from opti.core.config import ProjectRules
from opti.db.models import Document, Finding, RawItemRow
from opti.pipeline.enrichment import EnrichmentService
from opti.pipeline.processor import Processor
from opti.sdk.plan import build_query_plan
from opti.sdk.registry import Registry, load_instance_config
from opti.sdk.testing import make_context


def project(project_id: int, path: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": project_id,
        "visibility": "public",
        "path_with_namespace": path,
        "name": name,
        "description": "Public project metadata",
        "created_at": "2026-10-01T12:00:00Z",
        "web_url": "https://evil.example/redirect",
        "avatar_url": "https://evil.example/avatar.png",
        "readme_url": "https://evil.example/README",
        "owner": {"email": "must-not-be-stored@example.com"},
        **extra,
    }


def connector(rules: ProjectRules, handler: Any, **config: Any) -> GitLabProjectsConnector:
    return GitLabProjectsConnector(
        make_context(rules, connector_id="gitlab_projects", handler=handler),
        {"max_queries": 1, **config},
    )


def test_config_and_public_project_validation(sbr_rules: ProjectRules) -> None:
    registry = Registry()
    manifest = registry.manifest("gitlab_projects")
    instance = load_instance_config(Path("config/connectors"), manifest.id)
    assert manifest.category == "code" and not instance.enabled and not instance.license_approved
    assert _path("group/team/brand-project") == "group/team/brand-project"
    assert _path("group/../brand") is None
    assert _path("group/%2Fescape") is None
    assert _project(project(1, "group/brand", "SBR", visibility="private")) is None
    assert _project(project(1, "group/brand", "SBR", id=True)) is None
    with pytest.raises(ValueError, match="exclude_namespaces"):
        connector(
            sbr_rules, lambda _r: httpx.Response(200), exclude_namespaces=["bad/name"]
        ).validate_config()


async def test_search_filters_public_metadata_and_bounds_pagination(
    sbr_rules: ProjectRules,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        page = parse_qs(urlsplit(str(request.url)).query)["page"]
        if page == ["1"]:
            return httpx.Response(
                200,
                headers={"x-next-page": "2"},
                json=[
                    project(
                        101,
                        "outside/sample-brand",
                        "Sample Brand tools",
                        description="token=supersecret1234",
                    ),
                    project(102, "internal/sbr", "SBR internal", visibility="private"),
                ],
            )
        return httpx.Response(
            200,
            headers={"x-next-page": ""},
            json=[
                project(103, "outside/sample-brand-loan", "Sample Brand loan"),
                project(101, "outside/sample-brand", "Sample Brand tools"),
            ],
        )

    conn = connector(sbr_rules, handler, page_size=2, max_pages=2)
    conn.validate_config()
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert [item.source_item_id for item in items] == ["project:101", "project:103"]
    assert items[0].url == "https://gitlab.com/outside/sample-brand"
    assert "evil.example" not in json.dumps(items[0].payload)
    assert "must-not-be-stored" not in json.dumps(items[0].payload)
    assert "supersecret1234" not in json.dumps(items[0].payload)
    assert len(requests) == 2 and requests[0].url.path == "/api/v4/projects"
    params = parse_qs(urlsplit(str(requests[0].url)).query)
    assert params["visibility"] == ["public"] and params["simple"] == ["true"]
    assert params["per_page"] == ["2"]


async def test_excluded_namespace_and_errors(sbr_rules: ProjectRules) -> None:
    conn = connector(
        sbr_rules,
        lambda _r: httpx.Response(
            200, json=[project(1, "owned/sbr-project", "Sample Brand")]
        ),
        exclude_namespaces=["owned"],
    )
    assert [item async for item in conn.fetch(build_query_plan(sbr_rules))] == []
    for response in (
        httpx.Response(429),
        httpx.Response(302, headers={"location": "https://evil.example/"}),
        httpx.Response(200, json={"bad": "shape"}),
    ):
        conn = connector(sbr_rules, lambda _r, response=response: response)
        assert [item async for item in conn.fetch(build_query_plan(sbr_rules))] == []


@pytest.mark.db
async def test_public_project_candidate_scrubs_full_text(
    session: AsyncSession, sbr_rules: ProjectRules
) -> None:
    conn = connector(
        sbr_rules,
        lambda _r: httpx.Response(
            200, json=[project(301, "outside/sample-brand", "Sample Brand app")]
        ),
    )
    items = [item async for item in conn.fetch(build_query_plan(sbr_rules))]
    assert len(items) == 1
    result = await Processor(sbr_rules, EnrichmentService({})).process(session, items[0])
    assert len(result.findings) == 1
    finding = await session.get(Finding, result.findings[0])
    assert finding is not None and finding.category == "brand_mention"
    raw = (await session.scalars(select(RawItemRow))).one()
    doc = (await session.scalars(select(Document))).one()
    assert raw.payload["document"]["text"] == ""
    assert doc.url_normalized == "https://gitlab.com/outside/sample-brand"
    assert "evil.example" not in json.dumps(raw.payload)
