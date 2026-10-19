import asyncio
from datetime import UTC, datetime, timedelta

from opti.core.config import ProjectRules
from opti.db.models import Entity
from opti.pipeline.enrichment import EnrichmentService
from opti.sdk.testing import make_context, static_enricher
from opti.storage.artifacts import store_saver
from opti.storage.objects import MemoryObjectStore

NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def _entity() -> Entity:
    return Entity(
        type="domain", value="sbr-loans.com", first_seen=NOW, last_seen=NOW, enrichment={}
    )


async def test_results_are_cached_within_ttl(sbr_rules: ProjectRules) -> None:
    ctx = make_context(sbr_rules)
    dns = static_enricher(ctx, "dns", {"exists": True}, ttl=3600)
    clock = Clock()
    svc = EnrichmentService({"dns": dns}, clock=clock)
    e = _entity()
    assert await svc.enrich(e, ["dns"]) == {"dns": {"exists": True}}
    await svc.enrich(e, ["dns"])
    assert dns.calls == ["sbr-loans.com"]
    assert e.enrichment["dns"]["fetched_at"] == NOW.isoformat()
    clock.now = NOW + timedelta(seconds=3601)
    await svc.enrich(e, ["dns"])
    assert len(dns.calls) == 2


async def test_secret_scan_cache_accepts_only_redacted_fields(sbr_rules: ProjectRules) -> None:
    raw_secret = "AKIA" + "QYLPMN5HTWX2BVFC"
    scanner = static_enricher(
        make_context(sbr_rules),
        "secret_scan",
        {
            "supported": True,
            "scanned": True,
            "commit": "a" * 40,
            "depth": 100,
            "total": 1,
            "secrets": [
                {
                    "rule": "aws-access-token",
                    "description": f"key {raw_secret}",
                    "file": "config/app.env",
                    "line": 2,
                    "commit": "b" * 40,
                    "prefix": "AKIA",
                    "fingerprint": "f" * 64,
                    "length": 20,
                    "Secret": raw_secret,
                    "Author": "Jane Dev",
                }
            ],
            "Author": "Jane Dev",
        },
        types=("repo",),
    )
    entity = Entity(type="repo", value="github.com/acme/tools", first_seen=NOW,
                    last_seen=NOW, enrichment={})  # fmt: skip
    result = await EnrichmentService({"secret_scan": scanner}, clock=Clock()).enrich(
        entity, ["secret_scan"]
    )
    assert result["secret_scan"]["secrets"][0]["prefix"] == "AKIA"
    assert raw_secret not in str(result) and raw_secret not in str(entity.enrichment)
    assert "Jane Dev" not in str(entity.enrichment)


async def test_force_refreshes(sbr_rules: ProjectRules) -> None:
    dns = static_enricher(make_context(sbr_rules), "dns", {"exists": True})
    svc = EnrichmentService({"dns": dns}, clock=Clock())
    e = _entity()
    await svc.enrich(e, ["dns"])
    await svc.enrich(e, ["dns"], force=True)
    assert len(dns.calls) == 2


async def test_enricher_exception_is_recorded_not_cached(sbr_rules: ProjectRules) -> None:
    ctx = make_context(sbr_rules)
    bad = static_enricher(ctx, "rdap", RuntimeError("boom"))
    good = static_enricher(ctx, "dns", {"exists": True})
    svc = EnrichmentService({"rdap": bad, "dns": good}, clock=Clock())
    e = _entity()
    out = await svc.enrich(e, ["rdap", "dns"])
    assert out == {"rdap": {"error": "RuntimeError"}, "dns": {"exists": True}}
    assert "rdap" not in e.enrichment
    await svc.enrich(e, ["rdap"])
    assert len(bad.calls) == 2


async def test_error_payload_is_not_cached(sbr_rules: ProjectRules) -> None:
    ctx = make_context(sbr_rules)
    probe = static_enricher(ctx, "http_probe", {"reachable": False, "error": "TimeoutError"})
    dns = static_enricher(ctx, "dns", {"exists": True, "a": ["203.0.113.5"], "error": None})
    svc = EnrichmentService({"http_probe": probe, "dns": dns}, clock=Clock())
    e = _entity()
    out = await svc.enrich(e, ["http_probe", "dns"])
    assert out["http_probe"] == {"reachable": False, "error": "TimeoutError"}
    assert "http_probe" not in e.enrichment
    assert e.enrichment["dns"]["data"]["error"] is None
    await svc.enrich(e, ["http_probe", "dns"])
    assert len(probe.calls) == 2
    assert len(dns.calls) == 1

    probe.config["data"] = {"reachable": True, "title": "ok"}
    await svc.enrich(e, ["http_probe"])
    probe.config["data"] = {"reachable": False, "error": "TimeoutError"}
    forced = await svc.enrich(e, ["http_probe"], force=True)
    assert forced == {"http_probe": {"reachable": False, "error": "TimeoutError"}}
    assert e.enrichment["http_probe"]["data"] == {"reachable": True, "title": "ok"}


async def test_unknown_and_unsupported_are_skipped(sbr_rules: ProjectRules) -> None:
    ip_only = static_enricher(make_context(sbr_rules), "geoip", {"cc": "XX"}, types=("ip",))
    svc = EnrichmentService({"geoip": ip_only}, clock=Clock())
    assert await svc.enrich(_entity(), ["geoip", "nope"]) == {}
    assert svc.available == ("geoip",)


async def test_hung_enricher_times_out(sbr_rules: ProjectRules) -> None:
    """富化在处理事务内执行：卡住的富化器不能一直占着 worker 和数据库连接。"""
    slow = static_enricher(make_context(sbr_rules), "rdap", {"x": 1})

    async def hang(entity_type: str, value: str) -> dict[str, object]:
        await asyncio.sleep(30)
        return {}

    slow.enrich = hang  # type: ignore[method-assign]
    svc = EnrichmentService({"rdap": slow}, clock=Clock(), timeout=0.1)
    e = _entity()
    out = await asyncio.wait_for(svc.enrich(e, ["rdap"]), 5)
    assert out == {"rdap": {"error": "TimeoutError"}}
    assert "rdap" not in e.enrichment


async def test_recent_success_is_used_when_refresh_fails(sbr_rules: ProjectRules) -> None:
    """探测偶发失败时沿用一天内的成功结果：否则分数掉下去再升回来，会对同一域名重复告警。"""
    probe = static_enricher(make_context(sbr_rules), "http_probe", {"has_password_field": True})
    clock = Clock()
    svc = EnrichmentService({"http_probe": probe}, clock=clock)
    e = _entity()
    await svc.enrich(e, ["http_probe"])
    probe.config["data"] = {"reachable": False, "error": "ConnectError"}
    clock.now = NOW + timedelta(hours=2)
    assert await svc.enrich(e, ["http_probe"]) == {"http_probe": {"has_password_field": True}}
    assert len(probe.calls) == 2
    assert e.enrichment["http_probe"]["fetched_at"] == NOW.isoformat()
    # 强制刷新（监视列表复查）要看到真实的失败
    forced = await svc.enrich(e, ["http_probe"], force=True)
    assert forced == {"http_probe": {"reachable": False, "error": "ConnectError"}}
    # 超过一天就不再沿用
    clock.now = NOW + timedelta(hours=25)
    out = await svc.enrich(e, ["http_probe"])
    assert out == {"http_probe": {"reachable": False, "error": "ConnectError"}}


SHOT = {
    "final_url": "https://sbr-loans.com/",
    "artifacts": [{"name": "screenshot", "content_type": "image/png", "data_b64": "iVBORw0KGgo="}],
}


async def test_artifact_data_is_never_cached(sbr_rules: ProjectRules) -> None:
    """截图的 base64 不能写进 entity.enrichment：有存储时换成引用，没有存储时丢弃。"""
    store = MemoryObjectStore()
    shot = static_enricher(make_context(sbr_rules), "screenshot", SHOT, ttl=0)
    e = _entity()
    out = await EnrichmentService(
        {"screenshot": shot}, clock=Clock(), saver=store_saver(store)
    ).enrich(e, ["screenshot"])
    [ref] = out["screenshot"]["artifacts"]
    assert "data_b64" not in ref and store.objects[ref["key"]].startswith(b"\x89PNG")
    assert "data_b64" not in str(e.enrichment)
    bare = await EnrichmentService({"screenshot": shot}, clock=Clock()).enrich(
        _entity(), ["screenshot"]
    )
    assert bare["screenshot"]["artifacts"] == []


async def test_store_failure_becomes_error(sbr_rules: ProjectRules) -> None:
    async def broken(data: bytes, content_type: str) -> dict[str, object]:
        raise ConnectionError("s3 down")

    shot = static_enricher(make_context(sbr_rules), "screenshot", SHOT, ttl=0)
    e = _entity()
    out = await EnrichmentService({"screenshot": shot}, clock=Clock(), saver=broken).enrich(
        e, ["screenshot"]
    )
    assert out == {"screenshot": {"error": "ArtifactStoreError"}}
    assert "screenshot" not in e.enrichment


async def test_target_cache_does_not_reuse_homepage_or_other_path(sbr_rules: ProjectRules) -> None:
    probe = static_enricher(
        make_context(sbr_rules), "http_probe", {"status": 200}, types=("domain", "url")
    )
    svc = EnrichmentService({"http_probe": probe}, clock=Clock())
    e = _entity()
    await svc.enrich(e, ["http_probe"])
    a = {"http_probe": ("url", "https://sbr-loans.com/a")}
    b = {"http_probe": ("url", "https://sbr-loans.com/b")}
    await svc.enrich(e, ["http_probe"], targets=a)
    await svc.enrich(e, ["http_probe"], targets=a)
    probe.config["data"] = {"error": "TimeoutError"}
    assert await svc.enrich(e, ["http_probe"], targets=b) == {
        "http_probe": {"error": "TimeoutError"}
    }
    assert probe.calls == ["sbr-loans.com", a["http_probe"][1], b["http_probe"][1]]


async def test_platform_pages_are_never_visited(sbr_rules: ProjectRules) -> None:
    ctx = make_context(sbr_rules)
    probe = static_enricher(ctx, "http_probe", {"reachable": True}, types=("url", "domain"))
    shot = static_enricher(ctx, "screenshot", {"artifacts": []}, types=("url", "domain"))
    dns = static_enricher(ctx, "dns", {"exists": True}, types=("domain",))
    svc = EnrichmentService(
        {"http_probe": probe, "screenshot": shot, "dns": dns},
        no_visit=lambda host: host == "t.me" or host.endswith(".t.me"),
    )
    entity = Entity(
        type="url", value="https://t.me/fake_sbr", first_seen=NOW, last_seen=NOW, enrichment={}
    )
    out = await svc.enrich(
        entity, ("http_probe", "screenshot", "dns"), targets={"dns": ("domain", "t.me")}
    )
    assert probe.calls == [] and shot.calls == [] and "http_probe" not in out  # 平台页面不访问
    assert out["dns"] == {"exists": True}  # 不访问页面的查询照常
    assert not svc.visit_allowed("url", "https://t.me/fake_sbr") and svc.visit_allowed(
        "url", "https://sbr-x.top/"
    )
