import json
from typing import Any

import pytest
from websockets.asyncio.server import ServerConnection, serve

from opti.connectors.certstream.connector import CertstreamConnector
from opti.connectors.certstream.parser import parse_message
from opti.connectors.own_domain_ct.connector import OwnDomainCtConnector
from opti.core.config import ProjectRules
from opti.sdk.models import RawItem
from opti.sdk.plan import build_query_plan
from opti.sdk.testing import FakeTime, cert_msg, make_context

MESSAGES = [
    json.dumps({"message_type": "heartbeat"}),
    "not json",
    cert_msg(["crossbrace.com", "www.crossbrace.com"], sha="s1"),
    cert_msg(["sbr-loans.com", "www.sbr-loans.com"], sha="p1"),
    cert_msg(["mail.sbr.int"], sha="o1"),
]


async def _run(cls: type[CertstreamConnector], rules: ProjectRules, **config: Any) -> list[RawItem]:
    async def handler(ws: ServerConnection) -> None:
        for m in MESSAGES:
            await ws.send(m)

    async with serve(handler, "127.0.0.1", 0) as server:
        port = next(iter(server.sockets)).getsockname()[1]
        conn = cls(
            make_context(rules, connector_id=cls.id),
            {
                "url": f"ws://127.0.0.1:{port}/",
                "max_reconnects": 0,
                "reconnect_max_delay": 0,
                **config,
            },
        )
        return [i async for i in conn.fetch(build_query_plan(rules))]


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps({"message_type": "heartbeat"}),
        "not json",
        b"\x00\x01",
        json.dumps({"message_type": "certificate_update", "data": {}}),
        json.dumps(
            {"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": "x.com"}}}
        ),
        json.dumps([1, 2, 3]),
    ],
)
def test_parse_message_rejects_malformed(raw: str | bytes) -> None:
    assert parse_message(raw) is None


def test_parse_message_fields() -> None:
    e = parse_message(cert_msg(["sbr-loans.com"], sha="p1"))
    assert e is not None
    assert e.all_domains == ("sbr-loans.com",) and e.issuer_o == "Let's Encrypt"
    assert e.sha256 == "p1" and e.source == "Test Log" and e.not_before == 1790000000


async def test_certstream_emits_only_brand_matches(sbr_rules: ProjectRules) -> None:
    items = await _run(CertstreamConnector, sbr_rules)
    assert [i.source_item_id for i in items] == ["p1"]
    domains = {m["domain"] for m in items[0].payload["matches"]}
    assert domains == {"sbr-loans.com", "www.sbr-loans.com"}
    assert items[0].payload["cert"]["issuer_o"] == "Let's Encrypt"
    assert items[0].project_ids == ("sample-brand-protection",)


@pytest.mark.parametrize(
    ("approved", "expected"),
    [(["DigiCert Inc"], False), (["let's encrypt"], True), ([], None)],
)
async def test_own_domain_ct(
    sbr_rules: ProjectRules, approved: list[str], expected: bool | None
) -> None:
    items = await _run(OwnDomainCtConnector, sbr_rules, approved_issuers=approved)
    assert [i.source_item_id for i in items] == ["o1"]
    assert items[0].payload["issuer_approved"] is expected
    assert items[0].payload["matches"][0]["status"] == "official"


async def test_reconnects_with_backoff(sbr_rules: ProjectRules) -> None:
    t = FakeTime()
    calls: list[str] = []

    def failing_connect(url: str, **_kw: Any) -> Any:
        calls.append(url)
        raise OSError("connection refused")

    conn = CertstreamConnector(
        make_context(sbr_rules, connector_id="certstream"),
        {"url": "ws://nowhere/", "max_reconnects": 2, "reconnect_max_delay": 60},
        connect=failing_connect,
        sleep=t.sleep,
    )
    assert [i async for i in conn.fetch(build_query_plan(sbr_rules))] == []
    assert len(calls) == 3 and t.sleeps == [2.0, 4.0]


def test_same_domain_in_one_certificate_is_reported_once(sbr_rules: ProjectRules) -> None:
    from opti.connectors.certstream.parser import parse_message as parse

    conn = CertstreamConnector(
        make_context(sbr_rules, connector_id="certstream"), {"url": "ws://x/"}
    )
    event = parse(cert_msg(["sbr-loans.com", "*.sbr-loans.com", "www.sbr-loans.com"]))
    assert event is not None
    assert [m.domain for m in conn.select(event)] == ["sbr-loans.com", "www.sbr-loans.com"]
