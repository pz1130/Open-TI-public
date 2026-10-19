import io
import json
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from opti.cli import amain
from opti.core.visual import dhash_bytes
from opti.sandbox.favicon import favicon_fingerprint


async def test_logo_hash_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    image = Image.new("RGB", (80, 80), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((10, 8, 35, 70), fill="black")
    draw.polygon(((40, 70), (70, 40), (40, 20)), fill="black")
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    path = tmp_path / "logo.png"
    path.write_bytes(stream.getvalue())
    assert await amain(["logo-hash", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == {"dhash64": dhash_bytes(stream.getvalue())}
    assert await amain(["logo-hash", str(tmp_path / "missing.png")]) == 2


async def test_favicon_hash_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    stream = io.BytesIO()
    Image.new("RGB", (32, 32), "red").save(stream, format="PNG")
    path = tmp_path / "favicon.png"
    path.write_bytes(stream.getvalue())
    expected = favicon_fingerprint(stream.getvalue())
    assert expected is not None
    assert await amain(["favicon-hash", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "mmh3": expected["mmh3"],
        "sha256": expected["sha256"],
    }
    path.write_text("not an icon")
    assert await amain(["favicon-hash", str(path)]) == 2
