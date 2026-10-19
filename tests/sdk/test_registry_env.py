from pathlib import Path

import pytest

from opti.sdk.manifest import ManifestError
from opti.sdk.registry import load_instance_config


def _write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "c.yaml").write_text(body, encoding="utf-8")
    return tmp_path


def test_env_interpolation(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        'enabled: true\nconfig:\n  url: "${CT_URL:-ws://localhost:8080/}"\n  list: ["${A}", "x"]\n',
    )
    inst = load_instance_config(d, "c", env={"A": "1"})
    assert inst.config == {"url": "ws://localhost:8080/", "list": ["1", "x"]}
    inst = load_instance_config(d, "c", env={"A": "1", "CT_URL": "ws://ct:8080/"})
    assert inst.config["url"] == "ws://ct:8080/"


def test_missing_env_without_default(tmp_path: Path) -> None:
    d = _write(tmp_path, 'enabled: true\nconfig:\n  url: "${NOPE}"\n')
    with pytest.raises(ManifestError, match="NOPE"):
        load_instance_config(d, "c", env={})
