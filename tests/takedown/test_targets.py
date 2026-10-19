from pathlib import Path

from opti.takedown.config import TakedownConfig, load_takedown_config
from opti.takedown.hosting import HostData
from opti.takedown.targets import Target, clean_email, discover, escalations

REPO = Path(__file__).resolve().parents[2]
CFG = TakedownConfig.model_validate(
    {
        "providers": [
            {"id": "cdnco", "name": "CDN Co", "nameservers": [".ns.cdnco.example"],
             "network_names": ["CDNCO"], "channel": {"url": "https://abuse.cdnco.example/phishing"},
             "note": "also report to origin"},
        ],
        "reporting": [
            {"id": "browser", "name": "Browser Blocklist", "channel": {"url": "https://report.example/phish"}},
            {"id": "cn_only", "name": "CN Hotline", "tlds": ["cn"], "channel": {"email": "report@hotline.example"}},
        ],
        "escalation": [
            {"kind": "registrar", "name": "Registry Compliance", "channel": {"url": "https://compliance.example/"}},
        ],
    }
)  # fmt: skip
RDAP = {"registrar": "Cheap Registrar LLC", "abuse_email": "abuse@registrar.example", "nameservers": ["ns1.host.example"]}  # fmt: skip
LINODE = {"found": True, "network_name": "LINODE-US", "handle": "NET-45-33",
          "org": "Akamai Connected Cloud", "abuse_email": "abuse@linode.example"}  # fmt: skip


def test_registrar_hosting_and_reporting() -> None:
    out = discover(
        CFG, HostData("sbr-loans.com", RDAP, {"a": ["45.33.32.156"]}, {"45.33.32.156": LINODE})
    )
    assert [t.id for t in out.targets] == [
        "registrar:cheap-registrar-llc",
        "hosting:net-45-33",
        "report:browser",
    ]
    reg, host, rep = out.targets
    assert reg.email == "abuse@registrar.example" and reg.basis == "rdap_registrar"
    assert host.name == "Akamai Connected Cloud" and host.email == "abuse@linode.example"
    assert host.basis == "ip_rdap" and host.detail == "45.33.32.156"
    assert rep.url == "https://report.example/phish" and rep.email is None
    assert out.missing_hosting == []


def test_cdn_targets_and_missing_hosting() -> None:
    rdap = {**RDAP, "nameservers": ["anna.ns.cdnco.example", "bob.ns.cdnco.example"]}
    ips = {
        "104.16.1.1": {"found": True, "network_name": "CDNCO-NET", "org": "CDN Co"},
        "104.16.2.2": None,  # 还没查到
        "198.51.100.1": {"found": None, "error": "429"},  # 查询失败：既不算待查，也不产生对象
    }
    out = discover(CFG, HostData("login.sbr-pay.cn", rdap, {}, ips))
    assert [t.id for t in out.targets] == [
        "registrar:cheap-registrar-llc",
        "cdn:cdnco",
        "report:browser",
        "report:cn_only",
    ]
    cdn = out.targets[1]
    assert cdn.basis == "nameserver" and cdn.detail == "anna.ns.cdnco.example"
    assert cdn.note == "also report to origin" and cdn.url == "https://abuse.cdnco.example/phishing"
    assert out.missing_hosting == ["104.16.2.2"]
    assert out.get("cdn:cdnco") == cdn and out.get("hosting:nope") is None


def test_ip_host_has_no_registrar() -> None:
    out = discover(CFG, HostData("203.0.113.9", None, None, {"203.0.113.9": None}))
    assert [t.kind for t in out.targets] == ["report"]  # 没有 .cn 渠道：IP 没有顶级域
    assert out.missing_hosting == ["203.0.113.9"]


def test_rejects_injected_email() -> None:
    assert clean_email("abuse@registrar.example\r\nBcc: victim@example.org") is None
    assert clean_email("a@b.example, c@d.example") is None
    assert clean_email("<a@b.example>") is None
    assert clean_email("mailto:abuse@registrar.example") == "abuse@registrar.example"
    rdap = {**RDAP, "abuse_email": "x@y.example\nBcc: z@w.example"}
    assert discover(CFG, HostData("sbr-loans.com", rdap, None, {})).targets[0].email is None


def test_escalations_and_round_trip() -> None:
    [esc] = escalations(CFG, "registrar")
    assert esc.basis == "escalation" and esc.url == "https://compliance.example/"
    assert escalations(CFG, "hosting") == []
    t = discover(CFG, HostData("sbr-loans.com", RDAP, None, {})).targets[0]
    assert Target.from_dict(t.to_dict()) == t


def test_repository_config_loads() -> None:
    cfg = load_takedown_config(REPO / "config" / "takedown" / "platforms.yaml")
    assert cfg.sla_hours["registrar"] == 72 and cfg.providers and cfg.reporting and cfg.escalation
    assert load_takedown_config(REPO / "missing.yaml") == TakedownConfig()


def test_platform_host_targets_only_the_platform() -> None:
    from opti.takedown.config import Channel, Platform

    cfg = TakedownConfig(
        platforms=(
            Platform(
                id="telegram",
                name="Telegram",
                hosts=("t.me",),
                channel=Channel(email="abuse@telegram.org"),
                note="n",
            ),
        )
    )
    data = HostData(
        "t.me", {"registrar": "Some Registrar", "abuse_email": "abuse@reg.example"}, None, {}
    )
    found = discover(cfg, data)
    assert [(t.kind, t.id, t.email, t.basis, t.note) for t in found.targets] == [
        ("platform", "platform:telegram", "abuse@telegram.org", "platform", "n")
    ]
    lookalike = discover(
        cfg, HostData("t.me.evil.top", {"registrar": "R", "abuse_email": "a@r.example"}, None, {})
    )
    assert next(t.kind for t in lookalike.targets) == "registrar"
