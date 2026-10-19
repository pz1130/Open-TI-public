import json

from opti.core.config import ProjectRules
from opti.referer.logs import AccessRecord, RefererAggregator, parse_line

COMBINED = (
    "<190>Oct  2 08:00:00 web1 nginx: 203.0.113.9 - - [02/Oct/2026:08:00:00 +0000] "
    '"GET /static/logo.png HTTP/1.1" 200 5120 "https://secure-online-banking.top/login" "Mozilla/5.0"'
)


def test_parse_combined_with_syslog_header() -> None:
    assert parse_line(COMBINED) == AccessRecord(
        "secure-online-banking.top", "/static/logo.png", 200
    )


def test_parse_json_variants() -> None:
    nginx = json.dumps(
        {"request_uri": "/css/site.css?v=3", "status": 304, "http_referer": "https://clone.top/a"}
    )
    assert parse_line(f"<14>1 2026-10-02T08:00:00Z web1 nginx - - - {nginx}") == AccessRecord(
        "clone.top", "/css/site.css?v=3", 304
    )
    cf = json.dumps(
        {
            "ClientRequestPath": "/img/a.svg",
            "EdgeResponseStatus": 200,
            "ClientRequestReferer": "https://x.top/",
        }
    )
    assert parse_line(cf) == AccessRecord("x.top", "/img/a.svg", 200)


def test_parse_no_referer_and_garbage() -> None:
    no_ref = COMBINED.replace('"https://secure-online-banking.top/login"', '"-"')
    assert parse_line(no_ref) == AccessRecord(None, "/static/logo.png", 200)
    assert parse_line("random text") is None
    assert parse_line("{not json") is None


class Clock:
    def __init__(self) -> None:
        self.now = 1_790_000_000.0

    def __call__(self) -> float:
        return self.now


def _agg(rules: ProjectRules, clock: Clock) -> RefererAggregator:
    return RefererAggregator(rules, window=3600, min_hits=3, clock=clock)


def test_aggregates_hotlinks(sbr_rules: ProjectRules) -> None:
    clock = Clock()
    agg = _agg(sbr_rules, clock)
    for path in ("/static/logo.png", "/static/logo.png", "/css/site.css", "/js/app.js"):
        agg.add(AccessRecord("clone.top", path, 200))
    agg.add(AccessRecord("www.sbr.int", "/static/logo.png", 200))  # 官方站点自己
    agg.add(AccessRecord("www.google.com", "/static/logo.png", 200))  # 搜索引擎
    agg.add(AccessRecord("news.example", "/about.html", 200))  # 不是受保护的资源
    agg.add(AccessRecord("few.top", "/static/logo.png", 200))  # 次数不足
    agg.add(AccessRecord("err.top", "/static/logo.png", 404))
    assert agg.flush() == []  # 窗口未结束
    clock.now += 3601
    items = agg.flush()
    assert [i.payload["indicators"] for i in items] == [
        [{"type": "domain", "value": "clone.top", "volume": 4}]
    ]
    item = items[0]
    assert item.connector_id == "referer_log" and item.payload["signal"] == "hotlink"
    assert item.source_item_id == "clone.top:2026092114"
    assert sorted(item.payload["context"]["assets"]) == [
        "/css/site.css",
        "/js/app.js",
        "/static/logo.png",
    ]
    assert agg.flush(force=True) == []  # 已清空


def test_update_rules_switches_project_and_official(sbr_rules: ProjectRules) -> None:
    agg = _agg(sbr_rules, Clock())
    domains = sbr_rules.domains.model_copy(update={"official": ("clone.top",)})
    agg.update_rules(sbr_rules.model_copy(update={"project": "next", "domains": domains}))
    for host in ("clone.top", "secure-online-banking.top"):
        for _ in range(3):
            agg.add(AccessRecord(host, "/static/logo.png", 200))
    items = agg.flush(force=True)
    assert [i.project_ids for i in items] == [("next",)]
