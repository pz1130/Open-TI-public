import base64
import io

import mmh3
from PIL import Image

from opti.sandbox.favicon import MAX_ICON_BYTES, favicon_fingerprint, icon_url, same_origin


def _png() -> bytes:
    stream = io.BytesIO()
    Image.new("RGB", (32, 32), "red").save(stream, format="PNG")
    return stream.getvalue()


def test_favicon_hash_matches_shodan_base64_convention() -> None:
    data = _png()
    out = favicon_fingerprint(data)
    assert out is not None
    assert out["mmh3"] == mmh3.hash(base64.encodebytes(data), signed=True)
    assert out["size_bytes"] == len(data)
    assert len(str(out["sha256"])) == 64
    assert favicon_fingerprint(b"<svg></svg>" * 8) is None
    assert favicon_fingerprint(data + b"x" * MAX_ICON_BYTES) is None


def test_only_same_origin_icon_is_selected() -> None:
    page = "https://example.org/login"
    assert icon_url(page, None) == "https://example.org/favicon.ico"
    assert icon_url(page, "/assets/icon.png#fragment") == "https://example.org/assets/icon.png"
    assert icon_url(page, "https://other.example/icon.png") is None
    assert icon_url(page, "//example.org:444/icon.png") is None
    assert icon_url(page, "javascript:alert(1)") is None
    assert icon_url(page, "https://user@example.org/icon.png") is None
    assert not same_origin(page, "http://example.org/favicon.ico")
