from opti.alerting.config import AlertingConfig
from opti.alerting.dispatcher import AlertDispatcher, build_routes
from opti.alerting.runtime import ConfigBoundTickets, DispatcherCache
from opti.configs.runtime import ConfigSnapshot
from opti.core.config import ProjectRules
from opti.core.scoring import Severity
from opti.pipeline.app import current_app, set_app
from opti.pipeline.tasks import push_exposures, push_tickets
from opti.sdk.http import RateLimitedHttpClient
from opti.tickets.config import TicketsConfig

HOOK = "channel:teams:webhook_url"
CFG = AlertingConfig.model_validate({"teams": {"enabled": True}})


def _snap(rules: ProjectRules, url: str | None) -> ConfigSnapshot:
    return ConfigSnapshot.of(rules, alerting=CFG, alerting_secrets={HOOK: url})


async def test_dispatcher_rebuilds_on_secret_change(sbr_rules: ProjectRules) -> None:
    http = RateLimitedHttpClient()
    cache = DispatcherCache(
        lambda s: AlertDispatcher(s.alerting, build_routes(s.alerting, http, s.alerting_secrets))
    )
    first = _snap(sbr_rules, None)
    d1 = cache.get(first)
    assert cache.get(first) is d1 and d1.routes[0].sink is None
    d2 = cache.get(_snap(sbr_rules, "https://hook.example/x"))
    assert d2 is not d1 and d2.routes[0].sink is not None
    await http.aclose()


def test_dispatcher_rebuilds_when_active_project_changes(sbr_rules: ProjectRules) -> None:
    cache = DispatcherCache(lambda s: AlertDispatcher(s.alerting, [], project_id=s.rules.project))
    first = _snap(sbr_rules, None)
    old = cache.get(first)
    other = _snap(sbr_rules.model_copy(update={"project": "second"}), None)
    assert cache.get(other) is not old


async def test_ticket_wrapper_follows_snapshot(sbr_rules: ProjectRules) -> None:
    built: list[str | None] = []
    snaps = [_snap(sbr_rules, None)]

    class Client:
        name = "email"

        async def push(self, view, extra=None, *, idempotency_key=None, existing_ref=None):  # type: ignore[no-untyped-def]
            return "ok"

    def build(s: ConfigSnapshot) -> Client:
        built.append(s.alerting_secrets.get(HOOK))
        return Client()

    wrapper = ConfigBoundTickets(lambda: snaps[-1], build)
    assert wrapper.name == "email"
    assert await wrapper.push(None) == "ok"  # type: ignore[arg-type]
    snaps.append(_snap(sbr_rules, "https://hook.example/y"))
    await wrapper.push(None)  # type: ignore[arg-type]
    assert built == [None, "https://hook.example/y"]


class _UnavailableApp:
    """自动推送只应看见 tickets is None；一旦往下走就会碰数据库。"""

    def __init__(self, rules: ProjectRules) -> None:
        from opti.core.secretbox import Keyring

        self.keyring = Keyring(bytes(32))
        self.tickets = ConfigBoundTickets(lambda: _snap(rules, None), lambda _s: None)
        self.tickets_cfg = TicketsConfig(enabled=True, auto_push=(Severity.CRITICAL,))

    def sessions(self) -> None:
        raise AssertionError("unavailable ticket client was not skipped")


async def test_unavailable_client_is_not_pushed(sbr_rules: ProjectRules) -> None:
    previous = current_app()
    set_app(_UnavailableApp(sbr_rules))  # type: ignore[arg-type]
    try:
        assert await push_tickets() == 0
        assert await push_exposures() == 0
    finally:
        set_app(previous)
