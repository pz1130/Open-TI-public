from typing import Any

import dns.exception
import dns.resolver
import pytest

from opti.core.config import ProjectRules
from opti.enrichers.dns.enricher import DnsEnricher
from opti.enrichers.dns.resolver import DnspythonResolver, DnsRecords
from opti.sdk.testing import make_context


class _Rec:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


def _fake_resolve(table: dict[tuple[str, str], Any]):
    async def resolve(qname: str, rtype: str) -> list[_Rec]:
        v = table.get((qname, rtype), dns.resolver.NoAnswer())
        if isinstance(v, Exception):
            raise v
        return [_Rec(x) for x in v]

    return resolve


async def test_lookup_collects_records(monkeypatch: pytest.MonkeyPatch) -> None:
    r = DnspythonResolver()
    table = {
        ("xn--br-loans-jhh.com", "A"): ["203.0.113.5"],
        ("xn--br-loans-jhh.com", "MX"): ["10 mx.evil.example."],
        ("xn--br-loans-jhh.com", "NS"): ["ns2.host.example.", "ns1.host.example."],
    }
    monkeypatch.setattr(r._resolver, "resolve", _fake_resolve(table))
    rec = await r.lookup("ѕbr-loans.com")
    assert rec.a == ("203.0.113.5",)
    assert rec.mx == ("10 mx.evil.example",)
    assert rec.ns == ("ns1.host.example", "ns2.host.example")
    assert rec.exists is True and rec.error is None


async def test_lookup_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    r = DnspythonResolver()
    monkeypatch.setattr(
        r._resolver, "resolve", _fake_resolve({("gone.example", "A"): dns.resolver.NXDOMAIN()})
    )
    rec = await r.lookup("gone.example")
    assert rec.nxdomain and rec.exists is False


async def test_lookup_timeout_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    r = DnspythonResolver()
    monkeypatch.setattr(
        r._resolver, "resolve", _fake_resolve({("slow.example", "A"): dns.exception.Timeout()})
    )
    rec = await r.lookup("slow.example")
    assert rec.error == "Timeout" and rec.exists is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [(["ns1.x."], True), (dns.resolver.NXDOMAIN(), False), (dns.exception.Timeout(), None),
     (dns.resolver.NoAnswer(), True)],
)  # fmt: skip
async def test_is_registered(
    monkeypatch: pytest.MonkeyPatch, value: Any, expected: bool | None
) -> None:
    r = DnspythonResolver()
    monkeypatch.setattr(r._resolver, "resolve", _fake_resolve({("x.example", "NS"): value}))
    assert await r.is_registered("x.example") is expected


class _FakeResolver:
    async def lookup(self, name: str) -> DnsRecords:
        return DnsRecords(name, a=("198.51.100.1",))

    async def is_registered(self, name: str) -> bool | None:
        return True


async def test_dns_enricher(sbr_rules: ProjectRules) -> None:
    e = DnsEnricher(make_context(sbr_rules, connector_id="dns"), {}, resolver=_FakeResolver())
    out = await e.enrich("domain", "sbr-loans.com")
    assert tuple(out["a"]) == ("198.51.100.1",)
    assert out["exists"] is True
    assert e.supports("domain") and not e.supports("ip")


async def test_other_dns_errors_are_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    import dns.name

    r = DnspythonResolver()
    table = {
        ("x.example", "A"): dns.name.LabelTooLong(),
        ("x.example", "NS"): dns.name.LabelTooLong(),
    }
    monkeypatch.setattr(r._resolver, "resolve", _fake_resolve(table))
    rec = await r.lookup("x.example")
    assert rec.error == "LabelTooLong" and rec.exists is None
    assert await r.is_registered("x.example") is None


async def test_overlong_punycode_label_does_not_raise() -> None:
    r = DnspythonResolver(timeout=1)
    rec = await r.lookup("ѕbr" * 20 + ".com")
    assert rec.error == "LabelTooLong"
    assert await r.is_registered("ѕbr" * 20 + ".com") is None
