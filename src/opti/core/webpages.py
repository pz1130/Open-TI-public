"""首页内容类型判断。页面可访问不是对网站身份或仿冒行为的确认。"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from opti.core import policy
from opti.core.domains import parse_domain


def parking_signals(title: str, text: str) -> list[str]:
    body = text.casefold()
    heading = title.casefold()
    signals = [
        phrase
        for phrase in policy.current().pages.sale_phrases
        if phrase in body or phrase in heading
    ]
    if "for sale" in heading and (
        "domain" in heading or re.search(r"\b[a-z0-9-]+\.[a-z]{2,}\b", heading)
    ):
        signals.append("title:for sale")
    return signals


def page_kind(page: Mapping[str, Any]) -> str:
    status = page.get("status")
    if page.get("error") or not page.get("reachable") or not isinstance(status, int):
        return "unavailable"
    title, text = str(page.get("title") or ""), str(page.get("text_excerpt") or "")
    body = f"{title}\n{text}".casefold()
    if any(phrase in body for phrase in policy.current().pages.challenge_phrases):
        return "challenge"
    if not 200 <= status < 400:
        return "unavailable"
    final = urlsplit(str(page.get("final_url") or page.get("url") or ""))
    host = (final.hostname or "").lower().rstrip(".")
    if (
        page.get("parking_signals")
        or parking_signals(title, text)
        or any(
            host == parked or host.endswith("." + parked)
            for parked in policy.current().pages.parking_hosts
        )
        or (
            (host == "godaddy.com" or host.endswith(".godaddy.com"))
            and "/forsale/" in final.path.lower()
        )
    ):
        return "parking"
    content_type = str(page.get("content_type") or "").lower()
    if content_type and "html" not in content_type:
        return "non_html"
    if page.get("text_length") == 0 and not page.get("has_form"):
        return "empty"
    if page.get("has_password_field") and page.get("brand_terms"):
        return "phishing"
    original = urlsplit(str(page.get("url") or ""))
    old = parse_domain(original.hostname or "")
    new = parse_domain(host)
    if old and new and old.registered != new.registered:
        return "redirect"
    return "website"
