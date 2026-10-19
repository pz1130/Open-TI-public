"""数据库中加密保存的密钥（大模型供应商 API 密钥与出口代理）。

AES-256-GCM；主密钥来自环境变量 OPTI_ENCRYPTION_KEY（标准 Base64 编码的 32 字节），
轮换时旧钥放在 OPTI_ENCRYPTION_KEY_PREVIOUS，再运行 opti rekey。
密文格式：b"v1" + 主密钥指纹（sha256 前 8 字节）+ nonce（12 字节）+ 密文与标签。
所有错误消息都不含明文与密文。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"v1"
FINGERPRINT_LEN = 8
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
ENV_CURRENT = "OPTI_ENCRYPTION_KEY"
ENV_PREVIOUS = "OPTI_ENCRYPTION_KEY_PREVIOUS"
_HEAD = len(VERSION) + FINGERPRINT_LEN

log = logging.getLogger("opti.secretbox")


class SecretError(Exception):
    """主密钥缺失或无效，或密文无法解密。"""


def _fingerprint(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()[:FINGERPRINT_LEN]


def _parse(raw: str, name: str) -> bytes:
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise SecretError(f"{name} 不是合法的 Base64") from None
    if len(key) != KEY_LEN:
        raise SecretError(f"{name} 必须是 32 字节（Base64 编码后 44 个字符）")
    return key


def generate_key() -> str:
    return base64.b64encode(os.urandom(KEY_LEN)).decode()


class Keyring:
    def __init__(self, current: bytes, previous: bytes | None = None) -> None:
        if len(current) != KEY_LEN or (previous is not None and len(previous) != KEY_LEN):
            raise SecretError("主密钥必须是 32 字节")
        self._current = current
        self._keys = {_fingerprint(current): current}
        if previous is not None:
            self._keys.setdefault(_fingerprint(previous), previous)

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str] | None = None, *, state_dir: Path | None = None
    ) -> Keyring | None:
        """未配置返回 None；配置有误记错误日志并返回 None（服务照常启动，需要解密的功能不可用）。"""
        env = os.environ if environ is None else environ
        raw = (env.get(ENV_CURRENT) or "").strip()
        # 显式传入环境的单元测试不读取宿主机文件；平台各进程共享持久化目录。
        if not raw and (state_dir is not None or environ is None):
            path = master_key_path(state_dir or Path(env.get("OPTI_STATE_DIR") or "data"))
            try:
                raw = path.read_text(encoding="ascii").strip()
            except FileNotFoundError:
                pass
            except (OSError, UnicodeError):
                log.error("无法读取持久化主密钥文件")
                return None
        if not raw:
            return None
        previous = (env.get(ENV_PREVIOUS) or "").strip()
        try:
            return cls(
                _parse(raw, ENV_CURRENT), _parse(previous, ENV_PREVIOUS) if previous else None
            )
        except SecretError as e:
            log.error("主密钥配置有误，加密保存的密钥不可用：%s", e)
            return None

    def encrypt(self, plaintext: str, *, aad: str) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        sealed = AESGCM(self._current).encrypt(nonce, plaintext.encode(), aad.encode())
        return VERSION + _fingerprint(self._current) + nonce + sealed

    def decrypt(self, blob: bytes, *, aad: str) -> str:
        data = bytes(blob)
        if len(data) < _HEAD + NONCE_LEN + TAG_LEN or not data.startswith(VERSION):
            raise SecretError("密文格式不对")
        key = self._keys.get(data[len(VERSION) : _HEAD])
        if key is None:
            raise SecretError("密文由未知的主密钥加密（是否缺少 OPTI_ENCRYPTION_KEY_PREVIOUS？）")
        nonce, sealed = data[_HEAD : _HEAD + NONCE_LEN], data[_HEAD + NONCE_LEN :]
        try:
            return AESGCM(key).decrypt(nonce, sealed, aad.encode()).decode()
        except InvalidTag:
            raise SecretError("密文校验失败") from None

    def is_current(self, blob: bytes) -> bool:
        return bytes(blob)[len(VERSION) : _HEAD] == _fingerprint(self._current)


def master_key_path(state_dir: Path) -> Path:
    return state_dir / "secrets" / "master-key"


def initialize_master_key(state_dir: Path, raw: str) -> Keyring:
    """只允许首次写入；临时文件链接保证并发初始化时读者不会看到半个密钥。"""
    import tempfile

    keyring = Keyring(_parse(raw, ENV_CURRENT))
    path = master_key_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".master-key-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(raw.strip() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # 已存在时抛 FileExistsError，绝不覆盖旧主密钥
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)
    return keyring
