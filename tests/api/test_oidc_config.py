from pathlib import Path

import pytest
from pydantic import ValidationError

from opti.api.oidc.config import OidcConfig, load_oidc_config

REPO = Path(__file__).resolve().parents[2]
TENANT = "00000000-0000-4000-8000-000000000001"


def test_repository_default_is_disabled() -> None:
    assert load_oidc_config(REPO / "config" / "oidc.yaml").enabled is False
    assert load_oidc_config(REPO / "missing.yaml") == OidcConfig()


def test_entra_preset(tmp_path: Path) -> None:
    p = tmp_path / "oidc.yaml"
    p.write_text(
        f"enabled: true\nprovider: entra\ntenant_id: {TENANT}\nclient_id: app-1\n"
        "role_mapping:\n  analyst: [Opti.Analyst]\n  responder: [Opti.Responder, Opti.Lead]\n",
        encoding="utf-8",
    )
    cfg = load_oidc_config(p)
    assert cfg.effective_issuer == f"https://login.microsoftonline.com/{TENANT}/v2.0"
    assert cfg.roles_claim == "roles" and cfg.label == "Microsoft Entra ID"
    assert cfg.roles_for(["Opti.Lead", "Other"]) == ["responder"]
    assert cfg.roles_for(["Opti.Analyst", "Opti.Responder"]) == ["analyst", "responder"]
    assert cfg.roles_for([]) == []


def test_generic_defaults() -> None:
    cfg = OidcConfig(enabled=True, issuer="https://idp.example/realms/opti", client_id="opti",
                     role_mapping={"viewer": ("opti-viewers",)})  # fmt: skip
    assert cfg.effective_issuer == "https://idp.example/realms/opti"
    assert cfg.roles_claim == "groups" and cfg.username_claim == "preferred_username"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": "http://idp.example/realms/opti"},  # 非 https
        {"issuer": "https://"},
        {"issuer": "https://user:pass@idp.example/realms/opti"},
        {"issuer": "https://idp.example/realms/opti?x=y"},
        {"issuer": "https://idp.example", "role_mapping": {"root": ("admins",)}},  # 未知角色
        {"issuer": "https://idp.example", "allowed_algs": ("HS256",)},
        {"issuer": "https://idp.example", "allowed_algs": ("none",)},
        {"issuer": None},  # 启用但没有签发者
        {"issuer": "https://idp.example", "client_id": None},
        {"provider": "entra", "issuer": None, "tenant_id": "common"},  # 多租户签发者
        {"provider": "entra", "issuer": None, "tenant_id": None},
    ],
)
def test_invalid_configs(kwargs: dict[str, object]) -> None:
    base: dict[str, object] = {
        "enabled": True,
        "client_id": "opti",
        "issuer": "https://idp.example",
    }
    with pytest.raises(ValidationError):
        OidcConfig.model_validate({**base, **kwargs})


def test_http_allowed_only_when_explicit() -> None:
    cfg = OidcConfig(enabled=True, issuer="http://localhost:8080/realms/opti", client_id="opti",
                     allow_insecure_http=True)  # fmt: skip
    assert cfg.effective_issuer.startswith("http://")


def test_unknown_field_rejected(tmp_path: Path) -> None:
    p = tmp_path / "oidc.yaml"
    p.write_text("enabled: false\nclient_sercet: x\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_oidc_config(p)
