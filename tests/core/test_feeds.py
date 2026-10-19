from datetime import UTC, datetime

import pytest

from opti.core.feeds import MAX_FEED_BYTES, FeedError, parse_date, parse_feed, strip_html

RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Example News</title>
<item><title>Bank approves loan</title><link>https://news.example/a</link><guid>a-1</guid>
<description>&lt;p&gt;The &lt;b&gt;Sample Brand&lt;/b&gt; approved&lt;/p&gt;</description>
<pubDate>Thu, 02 Oct 2026 08:00:00 +0000</pubDate>
<source url="https://origin.example">Origin Paper</source></item>
<item><title>No link item</title><description>text</description></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>CERT</title>
<entry><title type="html">Advisory &amp;lt;1&amp;gt;</title><id>tag:cert.example,2026:1</id>
<link rel="alternate" href="https://cert.example/1"/><link rel="self" href="https://cert.example/1.xml"/>
<updated>2026-10-02T09:30:00Z</updated><summary>Summary one</summary></entry>
</feed>"""

RDF = b"""<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
<item rdf:about="https://r.example/1"><title>RDF item</title><link>https://r.example/1</link>
<dc:date>2026-10-02T10:00:00+08:00</dc:date></item></rdf:RDF>"""


def test_parse_rss() -> None:
    first, second = parse_feed(RSS)
    assert (
        first.guid == "a-1"
        and first.link == "https://news.example/a"
        and first.title == "Bank approves loan"
    )
    assert first.summary == "The Sample Brand approved"
    assert (
        first.published == datetime(2026, 10, 2, 8, tzinfo=UTC)
        and first.source_name == "Origin Paper"
    )
    assert second.link == "" and second.guid == "No link item"  # 没有 guid 与链接时用标题


def test_parse_atom_and_rdf() -> None:
    [entry] = parse_feed(ATOM)
    assert entry.link == "https://cert.example/1" and entry.guid == "tag:cert.example,2026:1"
    assert entry.title == "Advisory <1>" and entry.published == datetime(
        2026, 10, 2, 9, 30, tzinfo=UTC
    )
    [item] = parse_feed(RDF)
    assert item.link == "https://r.example/1" and item.published == datetime(
        2026, 10, 2, 2, tzinfo=UTC
    )


def test_parse_feed_rejects_xxe_and_garbage() -> None:
    xxe = b"""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<rss><channel><item><title>&x;</title></item></channel></rss>"""
    bomb = b"""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>
<rss><channel><item><title>&b;</title></item></channel></rss>"""
    for bad in (xxe, bomb, b"<html><body>not a feed", b"", b"x" * (MAX_FEED_BYTES + 1)):
        with pytest.raises(FeedError):
            parse_feed(bad)
    assert parse_feed(b"<rss><channel></channel></rss>") == []


def test_helpers() -> None:
    assert strip_html("<p>a&amp;b <br/> c</p>") == "a&b c"
    assert parse_date("Thu, 02 Oct 2026 08:00:00 GMT") == datetime(2026, 10, 2, 8, tzinfo=UTC)
    assert parse_date("2026-10-02") == datetime(2026, 10, 2, tzinfo=UTC)
    assert parse_date("not a date") is None and parse_date(None) is None
