import json
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker

from opti.api.app import openapi_schema
from opti.api.deps import ApiDeps
from opti.configs.runtime import ConfigRuntime
from opti.core.config import ProjectRules
from opti.settings import Settings

SNAPSHOT = Path(__file__).resolve().parents[2] / "web" / "src" / "api" / "openapi.json"


def test_openapi_snapshot_is_current(sbr_rules: ProjectRules) -> None:
    deps = ApiDeps(
        settings=Settings(),
        config=ConfigRuntime.static(sbr_rules),
        sessions=async_sessionmaker(),
        store=None,
    )
    current = json.loads(json.dumps(openapi_schema(deps)))
    committed = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert committed == current, (
        "接口有变化：运行 uv run opti api-schema > web/src/api/openapi.json && pnpm -C web run gen:api"
    )
