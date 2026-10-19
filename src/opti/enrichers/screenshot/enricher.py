"""截图存证富化器（设计文档 3.3 证据优先、10.2）：请隔离沙箱打开首页，返回截图与 HTML 快照。"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from typing import Any, ClassVar

from opti.collector import VERSION
from opti.core.domains import to_ascii
from opti.core.text_match import TextMatcher
from opti.core.visual import hash_distance, hash_usable
from opti.enrichers.http_probe.enricher import ascii_url, page_features
from opti.sdk.base import Enricher
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

MAX_DISTANCE = 8
MIN_MMH3 = -(2**31)
MAX_MMH3 = 2**31 - 1
MAX_OCR_CHARS = 16_000


def compare_logos(candidates: Any, references: Any) -> dict[str, Any] | None:
    if not isinstance(references, list) or not references:
        return None
    valid_candidates: list[dict[str, Any]] = []
    if isinstance(candidates, list):
        for candidate in candidates[:16]:
            if not isinstance(candidate, dict):
                continue
            fingerprint, box = candidate.get("dhash64"), candidate.get("box")
            if not isinstance(fingerprint, str) or not hash_usable(fingerprint):
                continue
            if not isinstance(box, dict):
                continue
            if any(type(box.get(k)) is not int for k in ("x", "y", "width", "height")):
                continue
            if (
                box["x"] < 0
                or box["y"] < 0
                or not 24 <= box["width"] <= 512
                or not 24 <= box["height"] <= 512
            ):
                continue
            valid_candidates.append(
                {"dhash64": fingerprint, "box": {k: box[k] for k in ("x", "y", "width", "height")}}
            )
    matches: list[dict[str, Any]] = []
    for reference in references[:12]:
        if not isinstance(reference, dict):
            continue
        name, fingerprint = reference.get("name"), reference.get("dhash64")
        if (
            not isinstance(name, str)
            or not isinstance(fingerprint, str)
            or not hash_usable(fingerprint)
        ):
            continue
        best: tuple[int, dict[str, Any]] | None = None
        for candidate in valid_candidates:
            distance = hash_distance(fingerprint, candidate["dhash64"])
            if best is None or distance < best[0]:
                best = (distance, candidate)
        if best is not None and best[0] <= MAX_DISTANCE:
            matches.append(
                {
                    "reference": name,
                    "distance": best[0],
                    "box": best[1]["box"],
                }
            )
    matches.sort(key=lambda m: m["distance"])
    return {
        "method": "dhash64",
        "threshold": MAX_DISTANCE,
        "candidate_count": len(valid_candidates),
        "possible_matches": matches[:3],
    }


def compare_favicon(value: Any, references: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    fingerprint = value.get("mmh3")
    sha256 = value.get("sha256")
    size = value.get("size_bytes")
    source = value.get("url")
    if (
        type(fingerprint) is not int
        or not MIN_MMH3 <= fingerprint <= MAX_MMH3
        or not isinstance(sha256, str)
        or len(sha256) != 64
        or any(c not in "0123456789abcdef" for c in sha256)
        or type(size) is not int
        or not 16 <= size <= 128 * 1024
        or not isinstance(source, str)
        or len(source) > 2048
    ):
        return None
    matches = []
    if isinstance(references, list):
        for reference in references[:12]:
            if (
                isinstance(reference, dict)
                and isinstance(reference.get("name"), str)
                and type(reference.get("mmh3")) is int
                and reference["mmh3"] == fingerprint
            ):
                matches.append(reference["name"][:80])
    return {
        "method": "mmh3-rfc2045-base64",
        "hash": fingerprint,
        "sha256": sha256,
        "size_bytes": size,
        "url": source,
        "reference_matches": matches[:3],
    }


def summarize_ocr(value: Any, matcher: TextMatcher) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    text = value[:MAX_OCR_CHARS]
    terms = sorted({hit.term for hit in matcher.match(text) if hit.role == "match"})[:12]
    return {"method": "tesseract-eng+chi_sim-psm11", "char_count": len(text), "brand_terms": terms}


def _result(
    d: Mapping[str, Any],
    logo_references: Any = None,
    favicon_references: Any = None,
    matcher: TextMatcher | None = None,
) -> dict[str, Any]:
    artifacts = [
        {"name": name, "content_type": content_type, "data_b64": d[key]}
        for name, content_type, key in (
            ("screenshot", "image/png", "screenshot_b64"),
            ("html", "text/html", "html_b64"),
        )
        if isinstance(d.get(key), str) and d[key]
    ]
    result = {
        "url": d.get("url"),
        "final_url": d.get("final_url"),
        "status": d.get("status"),
        "title": d.get("title"),
        "redirects": list(d.get("redirects") or []),
        "blocked": list(d.get("blocked") or []),
        "captured_at": d.get("captured_at"),
        "method": f"opti-sandbox/{VERSION} ({d.get('browser') or 'unknown'})",
        "artifacts": artifacts,
        "content_type": d.get("content_type"),
    }
    encoded = d.get("html_b64")
    if matcher is not None and isinstance(encoded, str) and len(encoded) <= 3_000_000:
        try:
            html = base64.b64decode(encoded, validate=True).decode("utf-8", errors="replace")
            visible = d.get("page_text")
            result.update(
                page_features(
                    html, matcher, visible_text=visible if isinstance(visible, str) else None
                )
            )
            result["title"] = str(d.get("title") or result.get("title") or "")[:300]
        except (binascii.Error, ValueError):
            pass
    comparison = compare_logos(d.get("visual_candidates"), logo_references)
    if comparison is not None:
        result["visual"] = comparison
    icon = compare_favicon(d.get("favicon"), favicon_references)
    if icon is not None:
        result["favicon"] = icon
    ocr = summarize_ocr(d.get("ocr_text"), matcher) if matcher is not None else None
    if ocr is not None:
        result["ocr"] = ocr
    return result


class ScreenshotEnricher(Enricher):
    id: ClassVar[str] = "screenshot"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("domain", "url")
    cache_ttl_seconds: ClassVar[int] = 0  # 每次都是新的存证，不复用

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        base = str(self.config.get("sandbox_url", "http://browser:8000")).rstrip("/")
        timeout = float(self.config.get("timeout", 20.0))
        if entity_type == "url":
            exact = ascii_url(value)
            if exact is None:
                return {"error": "invalid_url"}
            targets = [exact]
        else:
            host = to_ascii(value)
            targets = [f"https://{host}/", f"http://{host}/"]
        last: dict[str, Any] = {"error": "unreachable"}
        for target in targets:
            try:
                resp = await self.ctx.http().post_json(
                    f"{base}/capture",
                    {"url": target, "timeout": timeout},
                    timeout=timeout + 30,
                )
            except HttpError as e:
                return {"error": f"sandbox_unavailable: {e.status}"}
            data = resp.json()
            if not isinstance(data, dict):
                return {"error": "sandbox_bad_response"}
            if not data.get("error"):
                return _result(
                    data,
                    self.config.get("logo_hashes"),
                    self.config.get("favicon_hashes"),
                    TextMatcher(self.ctx.rules),
                )
            last = {
                "error": str(data["error"])[:300],
                "blocked": list(data.get("blocked") or [])[:20],
            }
        return last
