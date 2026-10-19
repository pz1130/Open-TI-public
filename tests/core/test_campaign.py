from collections import Counter

from opti.core.campaign import (
    Confirmed,
    Link,
    Node,
    fingerprints,
    group,
    group_signals,
    share_counts,
    shared_signals,
    signature,
)


def test_only_valid_exact_sha256_fingerprints_are_usable() -> None:
    good = "a" * 64
    assert fingerprints({"tls": {"data": {"sha256": good}}}) == {"tls_sha256": good}
    assert fingerprints({"tls": {"data": {"sha256": good.upper()}}}) == {}
    assert fingerprints({"screenshot": {"data": {"favicon": {"hash": -12345}}}}) == {}
    assert fingerprints({"screenshot": {"data": {"favicon": {"sha256": "a" * 63}}}}) == {}
    assert shared_signals(
        {"tls_sha256": good, "favicon_sha256": good},
        {"tls_sha256": good, "favicon_sha256": "b" * 64},
    ) == ["tls_sha256"]


TLS, ICON, HTML = "a" * 64, "b" * 64, "c" * 64
IP1, IP2, CDN = "93.184.216.34", "93.184.216.35", "104.16.0.1"
ALL = frozenset({"tls_sha256", "favicon_sha256", "html_sha256", "ip"})


def _enrichment(**kw: object) -> dict[str, object]:
    out: dict[str, object] = {}
    if "tls" in kw:
        out["tls"] = {"data": {"sha256": kw["tls"]}}
    if "icon" in kw:
        out["screenshot"] = {"data": {"favicon": kw["icon"]}}
    if "html" in kw:
        out["http_probe"] = {"data": {"html_sha256": kw["html"]}}
    if "a" in kw or "aaaa" in kw:
        out["dns"] = {"data": {"a": kw.get("a", []), "aaaa": kw.get("aaaa", [])}}
    return out


def test_group_signals_extracts_four_kinds() -> None:
    enrichment = _enrichment(
        tls=TLS, icon={"sha256": ICON, "reference_matches": []}, html=HTML,
        a=[IP1, "10.0.0.1", "127.0.0.1", "not-an-ip"], aaaa=["2606:4700:0:0:0:0:0:1", "fe80::1"],
    )  # fmt: skip
    assert group_signals("domain", enrichment) == {
        ("tls_sha256", TLS),
        ("favicon_sha256", ICON),
        ("html_sha256", HTML),
        ("ip", IP1),
        ("ip", "2606:4700::1"),
    }


def test_group_signals_rules_by_entity_type_and_format() -> None:
    enrichment = _enrichment(tls=TLS, icon={"sha256": ICON}, html=HTML, a=[IP1])
    # URL 实体没有 tls / dns 富化，即使有残留字段也不用
    assert group_signals("url", enrichment) == {("favicon_sha256", ICON), ("html_sha256", HTML)}
    assert group_signals("document", enrichment) == frozenset()
    assert group_signals("domain", None) == frozenset()
    bad = _enrichment(tls=TLS.upper(), icon={"hash": -1}, html="c" * 63, a=["203.0.113.5"])
    assert group_signals("domain", bad) == frozenset()  # 文档地址不是公网地址


def test_favicon_copied_from_own_brand_is_not_a_link() -> None:
    own = _enrichment(icon={"sha256": ICON, "reference_matches": ["Official icon"]})
    assert group_signals("domain", own) == frozenset()


def test_signature_is_order_independent() -> None:
    assert signature([3, 1, 2, 2]) == signature([1, 2, 3])
    assert signature([1, 2]) != signature([1, 2, 3])
    assert len(signature([1])) == 64


def _nodes(*specs: tuple[int, set[tuple[str, str]], bool]) -> list[Node]:
    return [Node(fid, frozenset(sig), active) for fid, sig, active in specs]


def _counts(nodes: list[Node]) -> Counter[tuple[str, str]]:
    return share_counts(n.signals for n in nodes)


def test_transitive_grouping_and_links() -> None:
    nodes = _nodes(
        (1, {("ip", IP1)}, True),
        (2, {("ip", IP1), ("tls_sha256", TLS)}, False),
        (3, {("tls_sha256", TLS)}, False),
        (4, {("ip", IP2)}, True),  # 孤立节点
    )
    result = group(nodes, _counts(nodes), [], max_share=10, min_members=2, enabled=ALL)
    assert [g.finding_ids for g in result.candidates] == [(1, 2, 3)]
    links = result.candidates[0].links
    assert links[1] == (Link("ip", IP1, 2),)
    assert links[2] == (Link("tls_sha256", TLS, 3), Link("ip", IP1, 1))  # 按信号种类顺序
    assert links[3] == (Link("tls_sha256", TLS, 2),)
    assert result.extensions == {}


def test_candidate_needs_an_open_alert_and_min_members() -> None:
    nodes = _nodes((1, {("ip", IP1)}, False), (2, {("ip", IP1)}, False))
    assert (
        group(nodes, _counts(nodes), [], max_share=10, min_members=2, enabled=ALL).candidates == ()
    )
    nodes = _nodes((1, {("ip", IP1)}, True), (2, {("ip", IP1)}, False))
    assert (
        group(nodes, _counts(nodes), [], max_share=10, min_members=3, enabled=ALL).candidates == ()
    )


def test_shared_values_are_ignored_and_reported() -> None:
    nodes = _nodes(
        (1, {("ip", CDN), ("html_sha256", HTML)}, True),
        (2, {("ip", CDN), ("html_sha256", HTML)}, True),
        (3, {("ip", CDN)}, True),
        (4, {("ip", CDN)}, True),
    )
    counts = _counts(nodes)
    assert counts[("ip", CDN)] == 4
    result = group(nodes, counts, [], max_share=3, min_members=2, enabled=ALL)
    assert [g.finding_ids for g in result.candidates] == [(1, 2)]
    group_ = result.candidates[0]
    assert group_.ignored == (("ip", CDN, 4),)
    assert group_.ignored_dicts() == [{"kind": "ip", "value": CDN, "count": 4}]
    assert group_.links[1] == (Link("html_sha256", HTML, 2),)


def test_disabled_signal_kinds_are_not_used() -> None:
    nodes = _nodes((1, {("ip", IP1)}, True), (2, {("ip", IP1)}, True))
    only_hashes = frozenset({"tls_sha256", "favicon_sha256", "html_sha256"})
    assert (
        group(
            nodes, _counts(nodes), [], max_share=10, min_members=2, enabled=only_hashes
        ).candidates
        == ()
    )


def test_confirmed_extension_respects_exclusions_and_owners() -> None:
    nodes = _nodes(
        (1, {("ip", IP1)}, True),  # 活动 10 成员
        (2, {("ip", IP1), ("html_sha256", HTML)}, True),  # 新：可达 10 → pending
        (3, {("html_sha256", HTML)}, True),  # 新：经 2 可达 → pending
        (
            4,
            {("html_sha256", HTML), ("tls_sha256", TLS)},
            True,
        ),  # 被活动 10 排除：不并入 10，也不让 10 经它扩展
        (5, {("tls_sha256", TLS), ("ip", IP2)}, True),  # 只能经 4 连到 10 → 不并入 10
        (6, {("ip", IP2)}, True),  # 活动 20 成员；5 与 6 共用 IP2
    )
    confirmed = [
        Confirmed(20, frozenset({6}), frozenset()),
        Confirmed(10, frozenset({1}), frozenset({4})),
    ]
    result = group(nodes, _counts(nodes), confirmed, max_share=10, min_members=2, enabled=ALL)
    # 编号小的活动先扩展：10 拿到 2、3，不经过被排除的 4
    assert result.extensions[10].finding_ids == (2, 3)
    assert result.extensions[10].links[2] == (Link("html_sha256", HTML, 3), Link("ip", IP1, 1))
    assert result.extensions[10].links[3] == (Link("html_sha256", HTML, 2),)
    # 20 从 6 经 IP2 拿到 5，再经 TLS 拿到 4（4 只被 10 排除）；不穿过 10 的成员 2、3
    assert result.extensions[20].finding_ids == (4, 5)
    assert result.extensions[20].links[5] == (Link("tls_sha256", TLS, 4), Link("ip", IP2, 6))
    assert result.candidates == ()


def test_lower_campaign_id_wins_a_contested_node() -> None:
    nodes = _nodes(
        (1, {("ip", IP1)}, True),
        (2, {("ip", IP1), ("ip", IP2)}, True),
        (3, {("ip", IP2)}, True),
    )
    confirmed = [
        Confirmed(30, frozenset({3}), frozenset()),
        Confirmed(7, frozenset({1}), frozenset()),
    ]
    result = group(nodes, _counts(nodes), confirmed, max_share=10, min_members=2, enabled=ALL)
    assert result.extensions[7].finding_ids == (2,)
    assert result.extensions[30].finding_ids == ()  # 不穿过活动 7 的成员 2
