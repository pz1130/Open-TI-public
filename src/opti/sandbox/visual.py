"""从已取得的浏览器截图提取视口内图片元素的局部指纹。"""

from __future__ import annotations

import io
import math
from collections.abc import Mapping, Sequence
from typing import Any

from PIL import Image

from opti.core.visual import dhash_image, hash_usable

MAX_CANDIDATES = 16
MAX_BOXES = 64
MIN_SIDE = 24
MAX_SIDE = 512


def image_candidates(png: bytes, boxes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """只裁剪已有截图，不访问图片 URL；忽略视口外、大图和无信息指纹。"""
    out: list[dict[str, Any]] = []
    with Image.open(io.BytesIO(png), formats=("PNG",)) as screenshot:
        screenshot.load()
        for box in boxes[:MAX_BOXES]:
            if len(out) >= MAX_CANDIDATES:
                break
            if not isinstance(box, Mapping):
                continue
            coords: list[float] = []
            for key in ("x", "y", "width", "height"):
                value = box.get(key)
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    break
                number = float(value)
                if not math.isfinite(number):
                    break
                coords.append(number)
            if len(coords) != 4:
                continue
            x, y, width, height = coords
            if not (MIN_SIDE <= width <= MAX_SIDE and MIN_SIDE <= height <= MAX_SIDE):
                continue
            if max(width / height, height / width) > 6:
                continue
            left, top = max(0, math.floor(x)), max(0, math.floor(y))
            right = min(screenshot.width, math.ceil(x + width))
            bottom = min(screenshot.height, math.ceil(y + height))
            if right - left < MIN_SIDE or bottom - top < MIN_SIDE:
                continue
            fingerprint = dhash_image(screenshot.crop((left, top, right, bottom)))
            if hash_usable(fingerprint):
                out.append(
                    {
                        "dhash64": fingerprint,
                        "box": {"x": left, "y": top, "width": right - left, "height": bottom - top},
                    }
                )
    return out


IMAGE_BOX_SCRIPT = """() => Array.from(document.images).slice(0, 64)
  .filter(img => img.complete && img.naturalWidth >= 24 && img.naturalHeight >= 24)
  .map(img => { const r = img.getBoundingClientRect();
    return {x: r.x, y: r.y, width: r.width, height: r.height}; })"""
