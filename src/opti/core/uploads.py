"""分析员上传的截图（设计文档 4.2）：按文件头核验真实格式，重新编码为 PNG 并去除全部元数据。

截图可能带分析员设备的位置、型号等元数据；只保留像素。原始文件的哈希另行记录，保证证据链。
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass

from PIL import Image, ImageOps, UnidentifiedImageError

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_SIDE = 8000
FORMATS = {"image/png": "PNG", "image/jpeg": "JPEG", "image/webp": "WEBP"}


class UploadError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class CleanImage:
    data: bytes  # 去除元数据后的 PNG
    original_sha256: str
    width: int
    height: int


def sniff(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def clean_image(data: bytes, declared: str) -> CleanImage:
    media = declared.split(";")[0].strip().lower()
    if media not in FORMATS:
        raise UploadError(415, "only PNG, JPEG and WebP screenshots are accepted")
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadError(413, "screenshot is larger than 10 MB")
    if sniff(data) != media:
        raise UploadError(415, "file content does not match its type")
    try:
        with Image.open(io.BytesIO(data), formats=[FORMATS[media]]) as img:
            if img.width > MAX_SIDE or img.height > MAX_SIDE:  # 只读文件头，解码前拦截
                raise UploadError(422, "screenshot is larger than 8000×8000 pixels")
            img.load()
            upright = ImageOps.exif_transpose(img)  # 去掉方向标记前先按它摆正
            mode = "RGBA" if upright.mode in ("RGBA", "LA", "P", "PA") else "RGB"
            pixels = upright.convert(mode)
    except UploadError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as e:
        raise UploadError(422, "screenshot could not be decoded") from e
    # 用像素重建新图像：不带 info、EXIF、ICC 等任何附加数据
    clean = Image.frombytes(pixels.mode, pixels.size, pixels.tobytes())
    out = io.BytesIO()
    clean.save(out, format="PNG")
    return CleanImage(out.getvalue(), hashlib.sha256(data).hexdigest(), clean.width, clean.height)
