import hashlib
import io

import pytest
from PIL import Image

from opti.core.uploads import MAX_UPLOAD_BYTES, UploadError, clean_image


def _image(fmt: str, size: tuple[int, int] = (40, 30), exif: bool = False) -> bytes:
    img = Image.new("RGB", size, "red")
    out = io.BytesIO()
    if exif:
        data = Image.Exif()
        data[0x010F] = "ACME Phone"
        img.save(out, format=fmt, exif=data)
    else:
        img.save(out, format=fmt)
    return out.getvalue()


@pytest.mark.parametrize(
    ("fmt", "media"), [("PNG", "image/png"), ("JPEG", "image/jpeg"), ("WEBP", "image/webp")]
)
def test_accepts_screenshots_and_reencodes_as_png(fmt: str, media: str) -> None:
    raw = _image(fmt)
    out = clean_image(raw, media)
    assert out.data.startswith(b"\x89PNG\r\n\x1a\n") and (out.width, out.height) == (40, 30)
    assert out.original_sha256 == hashlib.sha256(raw).hexdigest()


def test_strips_metadata() -> None:
    raw = _image("JPEG", exif=True)
    assert b"ACME Phone" in raw
    out = clean_image(raw, "image/jpeg; charset=binary")
    assert b"ACME Phone" not in out.data
    with Image.open(io.BytesIO(out.data)) as img:
        assert dict(img.getexif()) == {} and "exif" not in img.info


def test_rejects_wrong_or_unsupported_types() -> None:
    for declared, data in (
        ("image/png", _image("JPEG")),
        ("image/gif", b"GIF89a" + b"\0" * 20),
        ("text/plain", b"hello"),
        ("image/png", b"not an image"),
    ):
        with pytest.raises(UploadError) as e:
            clean_image(data, declared)
        assert e.value.status == 415


def test_rejects_oversized_and_broken() -> None:
    with pytest.raises(UploadError) as e:
        clean_image(b"\x89PNG\r\n\x1a\n" + b"\0" * MAX_UPLOAD_BYTES, "image/png")
    assert e.value.status == 413
    with pytest.raises(UploadError) as e:
        clean_image(_image("PNG", size=(8001, 1)), "image/png")
    assert e.value.status == 422
    with pytest.raises(UploadError) as e:
        clean_image(_image("PNG")[:40], "image/png")
    assert e.value.status == 422
