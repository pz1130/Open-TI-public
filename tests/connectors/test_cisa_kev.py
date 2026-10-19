import json
from typing import Any

import httpx

from opti.connectors.cisa_kev.connector import MIRROR, CisaKevConnector
from opti.core.config import ProjectRules
from opti.sdk.context import MemoryCursorStore
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context


def _entry(cve: str, **change: Any) -> dict[str, Any]:
    return {"cveID": cve, "vendorProject": "Example Networks", "product": "EdgeGate VPN",
            "vulnerabilityName": f"{cve} bypass", "dateAdded": "2026-10-01", "shortDescription": "d",
            "requiredAction": "patch", "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Unknown",
            "notes": "", "cwes": [], **change}  # fmt: skip


def _catalog(version: str, *entries: dict[str, Any]) -> dict[str, Any]:
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": version,
            "dateReleased": "2026-10-02T15:00:00.000Z", "count": len(entries), "vulnerabilities": list(entries)}  # fmt: skip


async def _run(rules: ProjectRules, cursors: MemoryCursorStore, make: Any) -> list[str]:
    conn = CisaKevConnector(
        make_context(rules, connector_id="cisa_kev", handler=lambda _r: make(), cursors=cursors), {}
    )
    return [i.payload["kev"]["cve"] async for i in conn.fetch(build_query_plan(rules))]


async def test_first_run_then_only_changes(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    v1 = _catalog("2026.10.01", _entry("CVE-2026-0001"), _entry("CVE-2026-0002"), _entry("bad"))
    assert await _run(sbr_rules, cursors, lambda: httpx.Response(200, json=v1)) == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    assert await _run(sbr_rules, cursors, lambda: httpx.Response(200, json=v1)) == []  # 版本未变
    v2 = _catalog("2026.10.02", _entry("CVE-2026-0001", knownRansomwareCampaignUse="Known"),
                  _entry("CVE-2026-0002"), _entry("CVE-2026-0003"))  # fmt: skip
    assert await _run(sbr_rules, cursors, lambda: httpx.Response(200, json=v2)) == [
        "CVE-2026-0001",
        "CVE-2026-0003",
    ]
    assert cursors.get("cisa_kev", "version") == "2026.10.02"
    assert set(json.loads(cursors.get("cisa_kev", "digests") or "{}")) == {
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    }
    v3 = _catalog("2026.10.03", _entry("CVE-2026-0001", knownRansomwareCampaignUse="Known"),
                  _entry("CVE-2026-0002"), _entry("CVE-2026-0003"))  # fmt: skip
    assert (
        await _run(sbr_rules, cursors, lambda: httpx.Response(200, json=v3)) == []
    )  # 新版本但内容未变


async def test_source_item_id_carries_digest(sbr_rules: ProjectRules) -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_catalog("v", _entry("CVE-2026-0001")))

    conn = CisaKevConnector(make_context(sbr_rules, connector_id="cisa_kev", handler=handler), {})
    [item] = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    cve, _, d = item.source_item_id.partition("#")
    assert cve == "CVE-2026-0001" and len(d) == 16 and item.url is None  # 内容变化后是新的原始条目


async def test_bad_catalog_keeps_cursor(sbr_rules: ProjectRules) -> None:
    cursors = MemoryCursorStore()
    good = _catalog("2026.10.01", _entry("CVE-2026-0001"))
    await _run(sbr_rules, cursors, lambda: httpx.Response(200, json=good))
    before = (cursors.get("cisa_kev", "version"), cursors.get("cisa_kev", "digests"))
    for make in (
        lambda: httpx.Response(200, html="<html>Access Denied</html>"),
        lambda: httpx.Response(503, text="maintenance"),
        lambda: httpx.Response(200, json={"catalogVersion": "2026.10.09"}),
        lambda: httpx.Response(200, json={**good, "count": 2}),
        lambda: httpx.Response(200, json=[]),
    ):
        assert await _run(sbr_rules, cursors, make) == []
        assert (cursors.get("cisa_kev", "version"), cursors.get("cisa_kev", "digests")) == before
    cursors.set("cisa_kev", "digests", "not json")  # 游标损坏时按第一次运行处理
    assert await _run(
        sbr_rules, cursors, lambda: httpx.Response(200, json=_catalog("x", _entry("CVE-2026-0001")))
    ) == ["CVE-2026-0001"]


async def test_cisa_403_uses_official_mirror(sbr_rules: ProjectRules) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) == MIRROR:
            return httpx.Response(200, json=_catalog("v", _entry("CVE-2026-0001")))
        return httpx.Response(403, text="Forbidden")

    conn = CisaKevConnector(make_context(sbr_rules, connector_id="cisa_kev", handler=handler), {})
    assert len([item async for item in conn.fetch(build_query_plan(sbr_rules))]) == 1
    assert len(seen) == 2 and seen[-1] == MIRROR
