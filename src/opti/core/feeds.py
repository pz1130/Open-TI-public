"""RSS 2.0 / RSS 1.0 / Atom 解析（设计文档 4.1）。外部 XML 用 defusedxml：拒绝 DTD、实体与外部引用。"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_ITEMS = 200
_TAGS = re.compile(r"<[^>]+>")


class FeedError(ValueError):
    pass


@dataclass(frozen=True)
class FeedItem:
    guid: str
    title: str
    link: str
    summary: str
    published: datetime | None
    source_name: str


def strip_html(text: str) -> str:
    """先去标签再反转义：XML 解析后得到的是 HTML 源码（如 `&lt;1&gt;` 是文字，不是标签）。"""
    return " ".join(html.unescape(_TAGS.sub(" ", text)).split())


def parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    try:
        dt = parsedate_to_datetime(v)
    except (TypeError, ValueError, IndexError):
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _local(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _child(el: Element, *names: str) -> Element | None:
    for name in names:
        for c in el:
            if _local(c.tag) == name:
                return c
    return None


def _text(el: Element | None) -> str:
    return "".join(el.itertext()).strip() if el is not None else ""


def _link(el: Element) -> str:
    for c in el:
        if _local(c.tag) != "link":
            continue
        href = c.get("href")
        if href is not None:  # Atom：只取 alternate（或未写 rel 的）链接
            if c.get("rel", "alternate") == "alternate":
                return href.strip()
        elif (c.text or "").strip():
            return (c.text or "").strip()
    return ""


def parse_feed(data: bytes) -> list[FeedItem]:
    if not data or len(data) > MAX_FEED_BYTES:
        raise FeedError("订阅源为空或超过 5 MB")
    try:
        root = fromstring(data, forbid_dtd=True)
    except (ParseError, DefusedXmlException) as e:
        raise FeedError(f"不是合法的 RSS / Atom：{type(e).__name__}") from e
    if _local(root.tag) not in ("rss", "feed", "RDF"):
        raise FeedError("不是 RSS / Atom 文档")
    items: list[FeedItem] = []
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        title = strip_html(_text(_child(el, "title")))
        link = _link(el)
        guid = _text(_child(el, "guid", "id")) or el.get(
            "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about", ""
        )
        items.append(
            FeedItem(
                guid=(guid or link or title)[:500],
                title=title[:500],
                link=link[:2000],
                summary=strip_html(_text(_child(el, "description", "summary", "content")))[:2000],
                published=parse_date(_text(_child(el, "pubDate", "published", "updated", "date"))),
                source_name=strip_html(_text(_child(el, "source")))[:200],
            )
        )
        if len(items) >= MAX_ITEMS:
            break
    return items
