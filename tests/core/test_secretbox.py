import base64
import logging

import pytest

from opti.core.secretbox import ENV_CURRENT, ENV_PREVIOUS, Keyring, SecretError, generate_key

OLD = bytes(range(32))
NEW = bytes(range(32, 64))
SECRET = "sk-" + "test-" + "0123456789abcdef"


def _b64(key: bytes) -> str:
    return base64.b64encode(key).decode()


def test_round_trip_and_format() -> None:
    ring = Keyring(NEW)
    blob = ring.encrypt(SECRET, aad="llm_provider:1:api_key")
    assert blob[:2] == b"v1" and SECRET.encode() not in blob
    assert ring.decrypt(blob, aad="llm_provider:1:api_key") == SECRET
    assert ring.encrypt(SECRET, aad="a") != ring.encrypt(SECRET, aad="a")  # 每次随机 nonce


def test_aad_and_tampering_are_rejected() -> None:
    ring = Keyring(NEW)
    blob = ring.encrypt(SECRET, aad="llm_provider:1:api_key")
    with pytest.raises(SecretError) as e:
        ring.decrypt(blob, aad="llm_provider:2:api_key")  # 挪到别的行
    assert SECRET not in str(e.value)
    with pytest.raises(SecretError):
        ring.decrypt(blob, aad="llm_provider:1:proxy")  # 挪到别的字段
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(SecretError):
        ring.decrypt(tampered, aad="llm_provider:1:api_key")
    with pytest.raises(SecretError):
        ring.decrypt(b"v2" + blob[2:], aad="llm_provider:1:api_key")
    with pytest.raises(SecretError):
        ring.decrypt(b"v1", aad="x")


def test_rotation() -> None:
    old_blob = Keyring(OLD).encrypt(SECRET, aad="a")
    with pytest.raises(SecretError, match="PREVIOUS"):
        Keyring(NEW).decrypt(old_blob, aad="a")
    both = Keyring(NEW, previous=OLD)
    assert both.decrypt(old_blob, aad="a") == SECRET
    assert not both.is_current(old_blob)
    assert both.is_current(both.encrypt(SECRET, aad="a"))


def test_from_env(caplog: pytest.LogCaptureFixture) -> None:
    assert Keyring.from_env({}) is None
    assert Keyring.from_env({ENV_CURRENT: "  "}) is None
    ring = Keyring.from_env({ENV_CURRENT: _b64(NEW), ENV_PREVIOUS: _b64(OLD)})
    assert ring is not None and ring.decrypt(Keyring(OLD).encrypt("x", aad="a"), aad="a") == "x"
    with caplog.at_level(logging.ERROR, logger="opti.secretbox"):
        assert Keyring.from_env({ENV_CURRENT: "not base64!"}) is None
        assert Keyring.from_env({ENV_CURRENT: _b64(bytes(16))}) is None
        assert Keyring.from_env({ENV_CURRENT: _b64(NEW), ENV_PREVIOUS: "bad"}) is None
    assert "OPTI_ENCRYPTION_KEY" in caplog.text


def test_generate_key() -> None:
    key = generate_key()
    assert len(base64.b64decode(key, validate=True)) == 32 and key != generate_key()
    assert Keyring.from_env({ENV_CURRENT: key}) is not None
