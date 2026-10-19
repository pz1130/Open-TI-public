from opti import organization as org_mod
from opti.configs.runtime import ConfigSnapshot
from opti.core.config import ProjectRules
from opti.gateway.app import create_gateway
from opti.gateway.testing import client_for, make_deps


async def test_rules_endpoint_follows_snapshot(sbr_rules: ProjectRules) -> None:
    deps, _ = make_deps(sbr_rules)
    app = create_gateway(deps)
    try:
        async with client_for(app) as c:
            first = (await c.get("/v1/rules")).json()
            deps.config.apply(ConfigSnapshot.of(sbr_rules.model_copy(update={"project": "next"})))
            second = (await c.get("/v1/rules")).json()
        assert first["rules"]["project"] == sbr_rules.project
        assert second["rules"]["project"] == "next" and second["digest"] != first["digest"]
    finally:
        org_mod.set_current(None)
