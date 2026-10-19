"""连接器 Manifest（设计文档 5.2）。"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any, Literal

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from opti.sdk.models import Tier

Category = Literal[
    "search_news", "social", "paste_forum", "code", "phishing", "ct", "breach",
    "ransomware", "darkweb", "threat_feed", "app_store", "image", "enrichment",
]  # fmt: skip
Kind = Literal["poll", "stream", "batch", "on_demand", "generator", "enricher", "sink"]


class ManifestError(Exception):
    """Manifest 或实例配置不合法。"""


class CredentialSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    required: bool = False
    secret: bool = True
    description: str = ""


class RateLimit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    per_second: float | None = Field(default=None, gt=0)
    per_minute: float | None = Field(default=None, gt=0)
    per_day: int | None = Field(default=None, gt=0)

    def requests_per_second(self) -> float | None:
        rates = [r for r in (self.per_second, self.per_minute and self.per_minute / 60) if r]
        return min(rates) if rates else None


class PlanSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requires: tuple[str, ...] = ()
    rate_limit: RateLimit = RateLimit()
    features: tuple[str, ...] = ()


class ScheduleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    default: str | None = None
    min_interval_seconds: int = Field(default=60, ge=0)


class ConnectorManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    name: str
    version: str
    category: Category
    kind: tuple[Kind, ...] = Field(min_length=1)
    tier: Tier
    entrypoint: str = Field(pattern=r"^[\w.]+:\w+$")
    homepage: str | None = None
    tos_url: str | None = None
    commercial_use: Literal["allowed", "restricted", "prohibited", "unknown"] = "unknown"
    last_reviewed: date | None = None
    requires_tor: bool = False
    egress: Literal["domestic", "overseas", "any"] = "overseas"
    darkweb: bool = False
    pii_risk: Literal["low", "medium", "high"] = "low"
    default_enabled: bool = False
    credentials: tuple[CredentialSpec, ...] = ()
    plans: dict[str, PlanSpec] = Field(default_factory=lambda: {"free": PlanSpec()})
    schedule: ScheduleSpec = ScheduleSpec()
    config_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    outputs: tuple[str, ...] = ()
    search_inputs: tuple[Literal["text", "domain"], ...] = ()
    compliance_notes: str = ""

    @field_validator("config_schema")
    @classmethod
    def _valid_schema(cls, v: dict[str, Any]) -> dict[str, Any]:
        try:
            Draft202012Validator.check_schema(v)
        except SchemaError as e:
            raise ValueError(f"config_schema 不是合法的 JSON Schema：{e.message}") from e
        return v

    @model_validator(mode="after")
    def _tor_only_for_darkweb(self) -> ConnectorManifest:
        if self.requires_tor and not self.darkweb:
            raise ValueError("requires_tor 只允许用于 darkweb: true 的连接器（设计文档 5.4）")
        return self


def load_manifest(path: Path) -> ConnectorManifest:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ManifestError(f"找不到 manifest：{path}") from None
    except yaml.YAMLError as e:
        raise ManifestError(f"{path} 不是合法的 YAML：{e}") from e
    try:
        return ConnectorManifest.model_validate(raw)
    except ValidationError as e:
        raise ManifestError(f"{path} 校验失败：\n{e}") from e


def validate_instance_config(
    manifest: ConnectorManifest, config: Mapping[str, Any]
) -> dict[str, Any]:
    """按 config_schema 校验实例配置，并为缺失的顶层字段填入 default。"""
    merged = dict(config)
    for key, prop in manifest.config_schema.get("properties", {}).items():
        if key not in merged and isinstance(prop, dict) and "default" in prop:
            merged[key] = copy.deepcopy(prop["default"])
    errors = sorted(
        Draft202012Validator(manifest.config_schema).iter_errors(merged),
        key=lambda e: [str(p) for p in e.path],
    )
    if errors:
        detail = "；".join(f"{'.'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors)
        raise ManifestError(f"连接器 {manifest.id} 的配置不合法：{detail}")
    return merged
