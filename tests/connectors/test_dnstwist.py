import pytest

from opti.connectors.dnstwist.connector import DnstwistConnector
from opti.core.config import ProjectRules
from opti.core.domain_match import DomainMatcher
from opti.enrichers.dns.resolver import DnsRecords
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import make_context


class FakeResolver:
    def __init__(self, registered: set[str], unknown: set[str] = frozenset()) -> None:
        self.registered = registered
        self.unknown = unknown
        self.checked: list[str] = []

    async def is_registered(self, name: str) -> bool | None:
        self.checked.append(name)
        if name in self.unknown:
            return None
        return name in self.registered

    async def lookup(self, name: str) -> DnsRecords:
        return DnsRecords(name, ns=("ns1.parking.example",))


CONFIG = {
    "tlds": ["com"],
    "long_token_fuzzers": ["replacement", "omission"],
    "short_token_fuzzers": ["homoglyph"],
    "max_candidates": 50000,
    "concurrency": 10,
}


@pytest.fixture
def conn(sbr_rules: ProjectRules) -> DnstwistConnector:
    resolver = FakeResolver({"sbr-loans.com", "orbitbamk.com"}, unknown={"sbrloans.com"})
    return DnstwistConnector(
        make_context(sbr_rules, connector_id="dnstwist"), CONFIG, resolver=resolver
    )


def test_candidates(conn: DnstwistConnector, sbr_rules: ProjectRules) -> None:
    cands = conn.candidates(build_query_plan(sbr_rules))
    assert {"sbr-loans.com", "sbrloans.com", "loginsbr.com", "sbr.com", "orbitbamk.com"} <= set(
        cands
    )
    assert "crossbrace.com" not in cands
    assert cands == sorted(set(cands))
    assert any(not c.isascii() for c in cands)  # 同形字变体
    matcher = DomainMatcher(sbr_rules.domains)
    assert all((m := matcher.match(c)) is not None and m.status == "match" for c in cands)


def test_candidates_are_capped(sbr_rules: ProjectRules) -> None:
    c = DnstwistConnector(
        make_context(sbr_rules, connector_id="dnstwist"),
        {**CONFIG, "max_candidates": 5},
        resolver=FakeResolver(set()),
    )
    assert len(c.candidates(build_query_plan(sbr_rules))) == 5


async def test_fetch_yields_only_registered(
    conn: DnstwistConnector, sbr_rules: ProjectRules
) -> None:
    items = [i async for i in conn.fetch(build_query_plan(sbr_rules))]
    assert {i.source_item_id for i in items} == {"sbr-loans.com", "orbitbamk.com"}
    item = next(i for i in items if i.source_item_id == "sbr-loans.com")
    assert tuple(item.payload["dns"]["ns"]) == ("ns1.parking.example",)
    assert item.payload["matches"][0]["status"] == "match"


def _token_of(matcher: DomainMatcher, domain: str) -> str:
    m = matcher.match(domain)
    assert m is not None
    return next(r.token for r in m.reasons if r.reason.value != "fraud_affix")


def test_cap_keeps_every_brand_token_and_all_short_token_candidates(
    sbr_rules: ProjectRules,
) -> None:
    ctx = make_context(sbr_rules, connector_id="dnstwist")
    matcher = DomainMatcher(sbr_rules.domains)
    plan = build_query_plan(sbr_rules)
    full = DnstwistConnector(
        ctx, {**CONFIG, "max_candidates": 10**6}, resolver=FakeResolver(set())
    ).candidates(plan)
    short = {d for d in full if _token_of(matcher, d) == "sbr"}
    cap = len(short) + 10
    assert cap < len(full)  # 确实发生了截断
    capped = DnstwistConnector(
        ctx, {**CONFIG, "max_candidates": cap}, resolver=FakeResolver(set())
    ).candidates(plan)
    assert len(capped) == cap
    assert short <= set(capped)  # 主品牌短词的候选一个都不能丢
    assert {_token_of(matcher, d) for d in capped} == {"sbr", "orbitbank", "samplebrand"}
