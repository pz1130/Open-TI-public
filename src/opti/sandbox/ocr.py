"""对已取证的视口 PNG 运行本地 OCR；完整文本不在此处持久化。"""

from __future__ import annotations

import asyncio
import os
from contextlib import suppress

MAX_PNG_BYTES = 8 * 1024 * 1024
MAX_TEXT_CHARS = 16_000
OCR_TIMEOUT = 8.0
OCR_LANGUAGES = "eng+chi_sim"


async def recognize(png: bytes) -> str | None:
    """返回截断的识别文本；缺少引擎、超时或失败时不影响原始截图。"""
    if not png.startswith(b"\x89PNG\r\n\x1a\n") or len(png) > MAX_PNG_BYTES:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "tesseract",
            "stdin",
            "stdout",
            "-l",
            OCR_LANGUAGES,
            "--psm",
            "11",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={**os.environ, "OMP_THREAD_LIMIT": "1"},
        )
    except OSError:
        return None
    try:
        output, _ = await asyncio.wait_for(proc.communicate(png), OCR_TIMEOUT)
    except TimeoutError:
        with suppress(ProcessLookupError):
            proc.kill()
        await proc.communicate()
        return None
    if proc.returncode != 0:
        return None
    return output.decode("utf-8", "replace")[:MAX_TEXT_CHARS]
