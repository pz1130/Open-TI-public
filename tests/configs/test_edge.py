import json

from opti.configs.edge import EdgeRules, valkey_fetch
from opti.configs.runtime import EDGE_RULES_KEY, EDGE_STATUS_KEY
from opti.configs.testing import FakeKV
from opti.core.config import ProjectRules


def _publish(kv: FakeKV, rules: ProjectRules, version: int, digest: str) -> None:
    kv.data[EDGE_RULES_KEY] = json.dumps(
        {"version": version, "digest": digest, "rules": rules.model_dump(mode="json")}
    )


async def test_edge_rules_follow_valkey(sbr_rules: ProjectRules) -> None:
    kv = FakeKV()
    edge = EdgeRules(sbr_rules, valkey_fetch(kv), process="intake@t", status=kv)
    assert await edge.refresh() is False  # 键不存在：保留文件规则
    seen: list[str] = []
    edge.subscribe(lambda r: seen.append(r.project))
    _publish(kv, sbr_rules.model_copy(update={"project": "next"}), 2, "d2")
    assert await edge.refresh() is True
    assert edge.current.project == "next" and seen == ["next"]
    assert await edge.refresh() is False  # digest 未变
    _publish(kv, sbr_rules.model_copy(update={"project": "older"}), 1, "d1")
    assert await edge.refresh() is False  # 旧版本不能使边缘规则回退
    assert edge.current.project == "next" and seen == ["next"]
    status = json.loads(kv.hashes[EDGE_STATUS_KEY]["intake@t"])
    assert status["version"] == 2 and status["digest"] == "d2" and status["error"] is None


async def test_edge_rules_keep_old_on_invalid(sbr_rules: ProjectRules) -> None:
    kv = FakeKV()
    edge = EdgeRules(sbr_rules, valkey_fetch(kv), process="syslog@t", status=kv)
    kv.data[EDGE_RULES_KEY] = json.dumps({"version": 3, "digest": "bad", "rules": {"project": ""}})
    assert await edge.refresh() is False
    assert edge.current is sbr_rules
    assert json.loads(kv.hashes[EDGE_STATUS_KEY]["syslog@t"])["error"].startswith("v3")


async def test_edge_rules_follow_file_rules_changed_at_same_version(
    sbr_rules: ProjectRules,
) -> None:
    # 只用 YAML 文件管理规则时版本号恒为 0；API 重启发布了改过的文件规则，边缘服务也要跟上。
    kv = FakeKV()
    edge = EdgeRules(sbr_rules, valkey_fetch(kv), process="intake@t", status=kv)
    _publish(kv, sbr_rules, 0, "file-a")
    assert await edge.refresh() is True
    _publish(kv, sbr_rules.model_copy(update={"project": "edited"}), 0, "file-b")
    assert await edge.refresh() is True
    assert edge.current.project == "edited"
    status = json.loads(kv.hashes[EDGE_STATUS_KEY]["intake@t"])
    assert status["version"] == 0 and status["digest"] == "file-b"
