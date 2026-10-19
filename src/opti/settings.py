"""运行参数：全部来自环境变量，便于容器部署。"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

COLLECTOR_MODES = ("local", "remote")


def _bool(value: str | None, default: bool, name: str) -> bool:
    if value is None or value == "":
        return default
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} 只能是 true/false，实际为 {value}")


@dataclass(frozen=True)
class Settings:
    database_url: str | None = None
    broker_url: str | None = None
    rules_path: Path = field(default=Path("config/projects/example/keywords.yaml"))
    organization_path: Path = field(default=Path("config/organization.yaml"))
    vendors_path: Path = field(default=Path("config/vendors.yaml"))
    software_path: Path = field(default=Path("config/software.yaml"))
    retention_config: Path = field(default=Path("config/retention.yaml"))
    campaigns_config: Path = field(default=Path("config/campaigns.yaml"))
    config_dir: Path = field(default=Path("config/connectors"))
    state_dir: Path = field(default=Path("data"))
    takedown_config: Path = field(default=Path("config/takedown/platforms.yaml"))
    takedown_templates: Path = field(default=Path("config/takedown/templates"))
    tickets_config: Path = field(default=Path("config/tickets.yaml"))
    alerting_config: Path = field(default=Path("config/alerting.yaml"))
    sharing_config: Path = field(default=Path("config/sharing.yaml"))
    # local：单机开发，全部连接器/富化器在本机运行；remote：egress=overseas 的交给境外采集节点（设计文档 3.4）
    collector_mode: str = "local"
    remote_timeout: float = 90.0  # 远程富化等待上限（秒），低于 EnrichmentService 的 120 秒
    s3_endpoint: str | None = None  # 为空时不启用证据存储
    s3_bucket: str = "opti-evidence"
    s3_region: str = "us-east-1"
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8443
    gateway_tls_cert: Path | None = None
    gateway_tls_key: Path | None = None
    gateway_client_ca: Path | None = None
    gateway_nodes: tuple[str, ...] = ()

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cookie_secure: bool = True  # 仅本机 http 开发时设为 false
    session_hours: int = 12
    local_login: bool = True  # 接入 OIDC 后本地口令登录只给应急账号用；设为 false 则完全关闭
    oidc_config: Path = field(default=Path("config/oidc.yaml"))
    web_dist: Path = field(default=Path("web/dist"))
    service_control_dir: Path | None = None  # 专用重启控制队列；非 Docker 部署默认关闭
    translation_socket: Path | None = None  # 自建翻译服务的本机 Unix socket；默认关闭

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        d = cls()

        def path(key: str, default: Path) -> Path:
            value = e.get(key)
            return Path(value) if value else default

        def opt_path(key: str) -> Path | None:
            value = e.get(key)
            return Path(value) if value else None

        mode = e.get("OPTI_COLLECTOR_MODE") or d.collector_mode
        if mode not in COLLECTOR_MODES:
            raise ValueError(
                f"OPTI_COLLECTOR_MODE 只能是 {'/'.join(COLLECTOR_MODES)}，实际为 {mode}"
            )
        nodes = tuple(
            n.strip() for n in (e.get("OPTI_GATEWAY_NODES") or "").split(",") if n.strip()
        )
        return cls(
            database_url=e.get("OPTI_DATABASE_URL") or None,
            broker_url=e.get("OPTI_BROKER_URL") or None,
            rules_path=path("OPTI_RULES", d.rules_path),
            organization_path=path("OPTI_ORGANIZATION", d.organization_path),
            vendors_path=path("OPTI_VENDORS", d.vendors_path),
            software_path=path("OPTI_SOFTWARE", d.software_path),
            retention_config=path("OPTI_RETENTION_CONFIG", d.retention_config),
            campaigns_config=path("OPTI_CAMPAIGNS_CONFIG", d.campaigns_config),
            config_dir=path("OPTI_CONFIG_DIR", d.config_dir),
            state_dir=path("OPTI_STATE_DIR", d.state_dir),
            takedown_config=path("OPTI_TAKEDOWN_CONFIG", d.takedown_config),
            takedown_templates=path("OPTI_TAKEDOWN_TEMPLATES", d.takedown_templates),
            tickets_config=path("OPTI_TICKETS_CONFIG", d.tickets_config),
            alerting_config=path("OPTI_ALERTING_CONFIG", d.alerting_config),
            sharing_config=path("OPTI_SHARING_CONFIG", d.sharing_config),
            collector_mode=mode,
            remote_timeout=float(e.get("OPTI_REMOTE_TIMEOUT") or d.remote_timeout),
            s3_endpoint=e.get("OPTI_S3_ENDPOINT") or None,
            s3_bucket=e.get("OPTI_S3_BUCKET") or d.s3_bucket,
            s3_region=e.get("OPTI_S3_REGION") or d.s3_region,
            gateway_host=e.get("OPTI_GATEWAY_HOST") or d.gateway_host,
            gateway_port=int(e.get("OPTI_GATEWAY_PORT") or d.gateway_port),
            gateway_tls_cert=opt_path("OPTI_GATEWAY_TLS_CERT"),
            gateway_tls_key=opt_path("OPTI_GATEWAY_TLS_KEY"),
            gateway_client_ca=opt_path("OPTI_GATEWAY_CLIENT_CA"),
            gateway_nodes=nodes,
            api_host=e.get("OPTI_API_HOST") or d.api_host,
            api_port=int(e.get("OPTI_API_PORT") or d.api_port),
            cookie_secure=_bool(e.get("OPTI_COOKIE_SECURE"), d.cookie_secure, "OPTI_COOKIE_SECURE"),
            session_hours=int(e.get("OPTI_SESSION_HOURS") or d.session_hours),
            local_login=_bool(e.get("OPTI_LOCAL_LOGIN"), d.local_login, "OPTI_LOCAL_LOGIN"),
            oidc_config=path("OPTI_OIDC_CONFIG", d.oidc_config),
            web_dist=path("OPTI_WEB_DIST", d.web_dist),
            service_control_dir=opt_path("OPTI_SERVICE_CONTROL_DIR"),
            translation_socket=opt_path("OPTI_TRANSLATION_SOCKET"),
        )
