from pathlib import Path

import pytest

from opti.sandbox import ocr


async def test_ocr_runs_locally_and_returns_bounded_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "tesseract"
    binary.write_text("#!/bin/sh\n/bin/cat >/dev/null\nprintf 'Sample Brand\\n'\n")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    png = b"\x89PNG\r\n\x1a\n" + b"test"
    assert await ocr.recognize(png) == "Sample Brand\n"
    assert await ocr.recognize(b"not a png") is None
    assert await ocr.recognize(png + b"x" * ocr.MAX_PNG_BYTES) is None


async def test_ocr_failure_does_not_block_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "tesseract"
    binary.write_text("#!/bin/sh\nexit 3\n")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert await ocr.recognize(b"\x89PNG\r\n\x1a\n" + b"test") is None


async def test_ocr_timeout_kills_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "tesseract"
    binary.write_text("#!/bin/sh\nexec /bin/sleep 2\n")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(ocr, "OCR_TIMEOUT", 0.01)
    assert await ocr.recognize(b"\x89PNG\r\n\x1a\n" + b"test") is None
