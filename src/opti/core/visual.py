"""局部图片 dHash：只提供人工复核线索，不把距离当作身份或仿冒证明。"""

from __future__ import annotations

import io
import re
import warnings

from PIL import Image, UnidentifiedImageError

MAX_REFERENCE_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 4_000_000
HASH_BITS = 64
HASH_PATTERN = re.compile(r"[0-9a-f]{16}\Z")


def dhash_image(image: Image.Image) -> str:
    """把透明图片铺到白底，计算水平相邻像素差异的 64 位哈希。"""
    if image.width < 24 or image.height < 24 or image.width * image.height > MAX_IMAGE_PIXELS:
        raise ValueError("图片尺寸超出 Logo 指纹范围")
    rgba = image.convert("RGBA")
    white = Image.new("RGBA", rgba.size, "white")
    gray = Image.alpha_composite(white, rgba).convert("L").resize((9, 8), Image.Resampling.LANCZOS)
    values = gray.tobytes()
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | int(values[row * 9 + col] > values[row * 9 + col + 1])
    return f"{bits:016x}"


def dhash_bytes(data: bytes) -> str:
    if len(data) > MAX_REFERENCE_BYTES:
        raise ValueError("图片文件过大")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data), formats=("PNG", "JPEG", "WEBP")) as image:
                return dhash_image(image)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombWarning) as exc:
        raise ValueError("无法读取支持的图片格式") from exc


def hash_usable(value: str) -> bool:
    """纯色、近乎全单向梯度的哈希区分力太低，不用于相似提示。"""
    if HASH_PATTERN.fullmatch(value) is None:
        return False
    try:
        bits = int(value, 16).bit_count()
    except ValueError:
        return False
    return 4 <= bits <= HASH_BITS - 4


def hash_distance(a: str, b: str) -> int:
    if not hash_usable(a) or not hash_usable(b):
        raise ValueError("Logo 指纹无效或区分力不足")
    return (int(a, 16) ^ int(b, 16)).bit_count()
