"""生成嵌入使用机构官网的金丝雀代码片段（设计文档 4.12）。"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from opti.core.domains import to_ascii

_SAFE_BASE = re.compile(r"^https://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9._~\-/]*)?$")


def canary_snippets(base_url: str, token: str, official_domains: Sequence[str]) -> tuple[str, str]:
    """返回 (JS, CSS)。JS 只在页面所在主机不是官方域名时报信；CSS 版本在每次页面加载时都会请求，
    适合放在不常加载的样式表中，或只在 JS 被骗子删除的情况下作为补充。"""
    base = base_url.rstrip("/")
    if not _SAFE_BASE.fullmatch(base) or not re.fullmatch(r"[A-Za-z0-9_\-]{16,128}", token):
        raise ValueError("base_url 必须是 https 地址且只含常规字符；令牌须为 16–128 位字母数字")
    _ = urlsplit(base).port  # Validate the numeric port range as well.
    domains = json.dumps([to_ascii(d.lower()) for d in official_domains], separators=(",", ":"))
    domains = domains.replace("<", r"\u003c").replace(">", r"\u003e").replace("&", r"\u0026")
    beacon = f"{base}/b/{token}.gif?v=js&h="
    js = (
        "<script>(function(){var o=" + domains + ";var h=location.hostname.toLowerCase();"
        "for(var i=0;i<o.length;i++){if(h===o[i]||h.slice(-o[i].length-1)==='.'+o[i])return;}"
        "new Image().src='" + beacon + "'+encodeURIComponent(h);})();</script>"
    )
    css = 'body{background-image:url("' + f"{base}/b/{token}.gif?v=css" + '")}'
    return js, css
