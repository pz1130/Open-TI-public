import base64
import io
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from PIL import Image, ImageDraw

pytest.importorskip("playwright")

from opti.core.visual import dhash_bytes, hash_distance
from opti.sandbox.service import PlaywrightCapture

pytestmark = pytest.mark.browser
PAGE = b"<html><head><title>SBR Secure Login</title></head><body><form method=post><input type=password></form></body></html>"


def _logo_png() -> bytes:
    image = Image.new("RGB", (80, 80), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((12, 8, 35, 72), fill="black")
    draw.polygon(((40, 70), (70, 40), (40, 20)), fill="black")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


LOGO = _logo_png()


class Handler(BaseHTTPRequestHandler):
    posted = 0
    logo_requests = 0
    icon_requests = 0

    def do_POST(self) -> None:
        type(self).posted += 1
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/js-sale":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Loading</title></head><body><script>location.replace('/sale');</script></body></html>"
            )
            return
        if self.path == "/sale":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Welcome</title></head><body><script>document.body.append('Buy this domain');</script></body></html>"
            )
            return
        if self.path == "/icon.png":
            type(self).icon_requests += 1
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(LOGO)
            return
        if self.path == "/favicon":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<html><head><title>Test</title><link rel="icon" href="/icon.png"></head>'
                b"<body>Evidence page</body></html>"
            )
            return
        if self.path == "/logo.png":
            type(self).logo_requests += 1
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(LOGO)
            return
        if self.path == "/logo":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<html><body><img src="/logo.png" width="80" height="80"></body></html>'
            )
            return
        if self.path == "/chain":
            self.send_response(302)
            self.send_header("Location", "/private")
            self.end_headers()
            return
        if self.path == "/private":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/")
            self.end_headers()
            return
        if self.path == "/old":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            PAGE
            + (
                b"<script>fetch('/submit', {method:'POST', body:'blocked'}).catch(()=>{});</script>"
                if self.path == "/post"
                else b""
            )
        )

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def site() -> Iterator[str]:
    Handler.logo_requests = 0
    Handler.icon_requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


async def test_capture_page_with_redirect(site: str) -> None:
    out = await PlaywrightCapture(allow_private=True)(f"{site}/old", 20)
    assert out["status"] == 200 and out["title"] == "SBR Secure Login"
    assert out["redirects"] == [f"{site}/old"]
    assert base64.b64decode(out["screenshot_b64"]).startswith(b"\x89PNG")
    assert b"password" in base64.b64decode(out["html_b64"])


async def test_javascript_redirect_and_visible_sale_text_are_captured(site: str) -> None:
    out = await PlaywrightCapture(allow_private=True)(f"{site}/js-sale", 20)
    assert out["title"] == "Welcome" and out["page_text"] == "Buy this domain"
    assert out["final_url"] == f"{site}/sale" and out["redirects"][0] == f"{site}/js-sale"
    assert out["content_type"].startswith("text/html")
    assert base64.b64decode(out["screenshot_b64"]).startswith(b"\x89PNG")
    assert "ocr_text" not in out


async def test_capture_fingerprints_visible_image_without_extra_lookup(site: str) -> None:
    out = await PlaywrightCapture(allow_private=True)(f"{site}/logo", 20)
    assert out["status"] == 200
    assert len(out["visual_candidates"]) == 1
    assert out["visual_candidates"][0]["box"]["width"] == 80
    assert hash_distance(out["visual_candidates"][0]["dhash64"], dhash_bytes(LOGO)) <= 8
    assert Handler.logo_requests == 1


async def test_capture_same_origin_favicon_after_evidence(site: str) -> None:
    from opti.sandbox.favicon import favicon_fingerprint

    out = await PlaywrightCapture(allow_private=True)(f"{site}/favicon", 20)
    assert out["status"] == 200 and out["title"] == "Test"
    assert out["final_url"] == f"{site}/favicon"
    assert b"Evidence page" in base64.b64decode(out["html_b64"])
    assert out["favicon"] == {"url": f"{site}/icon.png", **favicon_fingerprint(LOGO)}
    assert Handler.icon_requests == 1


async def test_capture_ocr_is_opt_in_and_uses_captured_png(
    site: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[bytes] = []

    async def fake_ocr(png: bytes) -> str:
        seen.append(png)
        return "Sample Brand"

    monkeypatch.setattr("opti.sandbox.service.recognize", fake_ocr)
    out = await PlaywrightCapture(allow_private=True, ocr_enabled=True)(f"{site}/old", 20)
    assert out["ocr_text"] == "Sample Brand"
    assert seen == [base64.b64decode(out["screenshot_b64"])]


async def test_capture_blocks_private_target(site: str) -> None:
    out = await PlaywrightCapture()(f"{site}/", 20)
    assert "error" in out and "screenshot_b64" not in out
    assert out["blocked"]


@pytest.mark.parametrize("path", ["/private", "/chain"])
async def test_capture_blocks_redirect_to_private_address(site: str, path: str) -> None:
    async def resolve(host: str, port: int) -> list[str]:
        return ["8.8.8.8"] if host == "localhost" else ["127.0.0.1"]

    url = site.replace("127.0.0.1", "localhost") + path
    out = await PlaywrightCapture(resolve=resolve)(url, 20)
    assert "error" in out and "screenshot_b64" not in out
    # DNS 检查放行了模拟公网地址；实际连接仍由代理钉在该地址，
    # 因而不会落到本地测试页面，也可能在 HTTP 重定向前就失败。


async def test_capture_blocks_script_post(site: str) -> None:
    Handler.posted = 0
    out = await PlaywrightCapture(allow_private=True)(site + "/post", 20)
    assert out["status"] == 200 and out["blocked"] == [site + "/submit"]
    assert Handler.posted == 0


async def test_browser_cannot_follow_dns_rebind_into_private_site(site: str) -> None:
    checks = 0

    async def resolve(host: str, port: int) -> list[str]:
        nonlocal checks
        assert host == "localhost" and port == int(site.rsplit(":", 1)[1])
        checks += 1
        return ["8.8.8.8"] if checks == 1 else ["127.0.0.1"]

    url = site.replace("127.0.0.1", "localhost") + "/"
    out = await PlaywrightCapture(resolve=resolve)(url, 20)
    assert checks >= 2
    assert "screenshot_b64" not in out and "error" in out
    assert out["blocked"]
