import httpx
import pytest

from opti.configs import kinds
from opti.connectors.google_news.connector import GoogleNewsConnector
from opti.core.config import ProjectRules
from opti.pipeline.domain_keywords import add
from opti.sdk.registry import Registry
from opti.sdk.scan import KeywordScan, node_rules_for_scan, scan_plan
from opti.sdk.testing import make_context


def test_domain_selection_does_not_send_text_searches(sbr_rules: ProjectRules) -> None:
    plan = scan_plan(
        sbr_rules,
        KeywordScan(
            project_id=sbr_rules.project, rules_version=0, scope="domain", term="samplebrand"
        ),
    )
    assert (
        plan.brand_tokens == ("samplebrand",)
        and plan.terms == ()
        and plan.restricted_tokens == ()
    )


@pytest.mark.parametrize("kind", ["brand", "restricted"])
def test_chinese_domain_keyword_is_preserved_in_manual_scan(
    sbr_rules: ProjectRules, kind: str
) -> None:
    rules = add(sbr_rules, kind, "样本", ["贷款"])
    plan = scan_plan(
        rules,
        KeywordScan(project_id=rules.project, rules_version=1, scope="domain", term="样本"),
    )
    assert plan.terms == ()
    assert plan.brand_tokens == (("样本",) if kind == "brand" else ())
    assert plan.restricted_tokens == ((("样本", ("贷款",)),) if kind == "restricted" else ())


@pytest.mark.parametrize("term", ["SBR", "not-saved"])
def test_unsaved_or_nonpublic_terms_are_rejected(sbr_rules: ProjectRules, term: str) -> None:
    with pytest.raises(ValueError, match="没有可扫描"):
        scan_plan(
            sbr_rules,
            KeywordScan(project_id=sbr_rules.project, rules_version=0, scope="text", term=term),
        )


async def test_new_phrase_beyond_query_limit_is_actually_searched(sbr_rules: ProjectRules) -> None:
    data = kinds.to_data("rules", sbr_rules)
    data["sets"]["brand"]["terms"].append(
        {"value": "A Newly Added Brand", "mode": "phrase", "remote_search": True}
    )
    rules = kinds.parse("rules", kinds.from_data("rules", data))
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params["q"])
        return httpx.Response(200, content=b"<rss><channel/></rss>")

    conn = GoogleNewsConnector(
        make_context(rules, connector_id="google_news", handler=handler), {"max_queries": 1}
    )
    plan = scan_plan(
        rules,
        KeywordScan(
            project_id=rules.project, rules_version=1, scope="text", term="A Newly Added Brand"
        ),
    )
    assert [item async for item in conn.fetch(plan)] == []
    assert seen == ['"A Newly Added Brand"']
    await conn.ctx.http().aclose()


def test_search_capabilities_are_explicit_and_streams_are_not_requested() -> None:
    manifests = Registry().manifests()
    assert {m.id for m in manifests if "domain" in m.search_inputs} == {
        "crtsh",
        "dnstwist",
        "urlscan",
    }
    assert {m.id for m in manifests if "text" in m.search_inputs} == {
        "google_news",
        "brave_news",
        "gdelt_doc",
        "urlscan",
        "otx",
        "reddit_search",
        "gitlab_projects",
        "app_store_search",
    }


def test_manual_node_snapshot_excludes_private_and_local_only_terms(
    sbr_rules: ProjectRules,
) -> None:
    data = kinds.to_data("rules", sbr_rules)
    data["sets"]["internal"] = {
        "role": "match",
        "type": "brand",
        "private": True,
        "terms": [{"value": "PrivateBrand"}],
    }
    rules = kinds.parse("rules", kinds.from_data("rules", data))
    saved = node_rules_for_scan(rules)
    assert "internal" not in saved["sets"]
    assert all(
        not group["private"]
        and group["type"] != "executive"
        and all(term["remote_search"] for term in group["terms"])
        for group in saved["sets"].values()
    )
    safe = ProjectRules.model_validate(saved)
    assert scan_plan(
        safe,
        KeywordScan(
            project_id=safe.project, rules_version=0, scope="text", term="Sample Brand"
        ),
    ).terms
