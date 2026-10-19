import io

import pytest
from PIL import Image, ImageDraw

from opti.core.visual import dhash_bytes, dhash_image, hash_distance, hash_usable


def _logo() -> Image.Image:
    image = Image.new("RGB", (80, 80), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((12, 8, 35, 72), fill="black")
    draw.polygon(((40, 70), (70, 40), (40, 20)), fill="black")
    return image


def test_dhash_is_stable_and_low_information_is_rejected() -> None:
    image = _logo()
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    fingerprint = dhash_image(image)
    assert dhash_bytes(stream.getvalue()) == fingerprint
    assert hash_usable(fingerprint) and hash_distance(fingerprint, fingerprint) == 0
    assert not hash_usable(dhash_image(Image.new("RGB", (80, 80), "white")))
    with pytest.raises(ValueError):
        hash_distance("0000000000000000", fingerprint)


def test_invalid_and_oversize_images_are_rejected() -> None:
    with pytest.raises(ValueError):
        dhash_bytes(b"not an image")
    with pytest.raises(ValueError):
        dhash_bytes(b"a" * (8 * 1024 * 1024 + 1))
    with pytest.raises(ValueError):
        dhash_image(Image.new("RGB", (10, 10), "white"))
