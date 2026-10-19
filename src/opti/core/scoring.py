"""规则评分 v1（设计文档 9.2）。

S1 只启用 domain_risk、content_risk、intel_hits、benign_signals 四个因子；
富化观测值为 None 表示尚未观测，不加分也不减分。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from opti.core import policy
from opti.core.domain_match import DomainMatch, Reason
from opti.core.urls import UrlMatch


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    PHISHING_SITE = "phishing_site"
    TYPOSQUAT_DOMAIN = "typosquat_domain"
    UNAPPROVED_CERTIFICATE = "unapproved_certificate"
    CERTIFICATE_EXPIRY = "certificate_expiry"
    REPORTED_PHISHING = "reported_phishing"  # 员工或公众举报（设计文档 4.12）
    CLONE_SITE = "clone_site"  # 金丝雀回调或官网资源被盗链
    EMAIL_SPOOFING = "email_spoofing"  # DMARC 未通过的冒用发件
    CREDENTIAL_EXPOSURE = "credential_exposure"  # 员工邮箱出现在泄露事件或窃密木马记录中
    RANSOMWARE_MENTION = "ransomware_mention"  # 本机构或关键供应商被列为勒索泄露站受害者
    SECRET_LEAK = "secret_leak"  # 公开代码中泄露的密钥
    DATA_LEAK = "data_leak"  # 公开代码中出现的本机构内部信息
    BRAND_MENTION = "brand_mention"  # 一般提及：信息性，默认不告警
    NEGATIVE_PRESS = "negative_press"  # 负面舆情
    FRAUD_SCAM = "fraud_scam"  # 冒用名义的诈骗
    VULNERABILITY = "vulnerability"
    THREAT_INTEL = "threat_intel"
    IMPERSONATION_ACCOUNT = (
        "impersonation_account"  # 冒充本机构的社交账号或主页（人工提交或自动检测）
    )


_BASE = {Category.PHISHING_SITE: 40, Category.TYPOSQUAT_DOMAIN: 20}
_STRENGTH = {
    Reason.OFFICIAL_EMBEDDED: 25,
    Reason.HOMOGLYPH: 22,
    Reason.BRAND_LABEL: 18,
    Reason.BRAND_COMBO: 18,
    Reason.BRAND_FUZZY: 15,
    Reason.BRAND_SUBSTRING: 12,
}
# 仿冒与钓鱼中常见的低价/新通用顶级域
RISKY_TLDS = frozenset(
    {"top", "xyz", "icu", "buzz", "cfd", "sbs", "click", "online", "site", "shop", "live",
     "vip", "cyou", "rest", "bond", "lat", "work", "support", "info"}
)  # fmt: skip


@dataclass(frozen=True)
class DomainSignals:
    match: DomainMatch
    age_days: int | None = None
    resolves: bool | None = None
    has_mx: bool | None = None
    has_login_form: bool | None = None
    brand_in_content: bool | None = None
    logo_similar: bool | None = None
    tranco_rank: int | None = None
    intel_hit: bool | None = None


@dataclass(frozen=True)
class Score:
    value: int
    severity: Severity
    category: Category
    breakdown: dict[str, int]


def severity_for(value: int) -> Severity:
    if value >= policy.current().risk.critical_score:
        return Severity.CRITICAL
    if value >= policy.current().risk.high_score:
        return Severity.HIGH
    if value >= policy.current().risk.medium_score:
        return Severity.MEDIUM
    if value >= policy.current().risk.low_score:
        return Severity.LOW
    return Severity.INFO


_SEVERITY_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
ALERT_FROM = Severity.MEDIUM
LLM_POINTS = {"yes": 10, "no": -30, "unsure": 0}


def with_llm(score: Score, verdict: str) -> Score:
    """Apply the model verdict as one replaceable scoring factor."""
    breakdown = {
        **{k: v for k, v in score.breakdown.items() if k != "llm"},
        "llm": getattr(policy.current().risk, f"llm_{verdict}_points"),
    }
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), score.category, breakdown)


def alert_threshold() -> int:
    """Score at which the configured alert level starts."""
    risk = policy.current().risk
    return int(getattr(risk, f"{risk.alert_from}_score"))


def with_code_llm(score: Score, secret_verdict: str, relation: str) -> Score:
    """Apply code-secret verdicts as two factors; never below the alert line the rules reached."""
    risk = policy.current().risk
    rule = {k: v for k, v in score.breakdown.items() if not k.startswith("llm")}
    rule_value = max(0, min(100, sum(rule.values())))
    breakdown = {
        **rule,
        "llm_secret": {
            "real": risk.llm_code_real_points,
            "example": risk.llm_code_example_points,
        }.get(secret_verdict, 0),
        "llm_relation": {
            "org": risk.llm_code_org_points,
            "related": risk.llm_code_related_points,
            "unrelated": risk.llm_code_unrelated_points,
        }.get(relation, 0),
    }
    floor = min(rule_value, alert_threshold())
    if sum(breakdown.values()) < floor:
        breakdown["llm_floor"] = floor - sum(breakdown.values())
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), score.category, breakdown)


def severity_rank(severity: Severity | str) -> int:
    return _SEVERITY_ORDER.index(Severity(severity))


def score_own_domain_cert(issuer_approved: bool | None) -> Score | None:
    """使用机构 自有域名出现未经批准的 CA 签发的证书（设计文档 4.5）：固定 70 分（High）。

    未配置批准清单（None）或 CA 已批准（True）时不产生 Finding。
    """
    if issuer_approved is not False:
        return None
    return Score(70, severity_for(70), Category.UNAPPROVED_CERTIFICATE, {"base": 70})


def score_domain(sig: DomainSignals) -> Score:
    m = sig.match
    if m.status != "match":
        raise ValueError(
            f"只对 status == 'match' 的域名评分（当前为 {m.status}）：官方资产与已知合法相似方不产生 Finding"
        )
    phishing = bool(sig.intel_hit) or bool(
        sig.has_login_form and (sig.brand_in_content or sig.logo_similar)
    )
    category = Category.PHISHING_SITE if phishing else Category.TYPOSQUAT_DOMAIN

    strength = max((_STRENGTH.get(r.reason, 0) for r in m.reasons), default=0)
    if m.subdomain_only:
        strength //= 2
    domain = strength
    if m.has(Reason.FRAUD_AFFIX):
        domain += 5
    if m.registered.rsplit(".", 1)[-1] in RISKY_TLDS:
        domain += 5
    if sig.age_days is not None and sig.age_days < 30:
        domain += 5
    if sig.has_mx:
        domain += 5

    content = (
        (15 if sig.has_login_form else 0)
        + (10 if sig.brand_in_content else 0)
        + (10 if sig.logo_similar else 0)
    )

    benign = 0
    if sig.tranco_rank is not None:
        if sig.tranco_rank <= 100_000:
            benign += 30
        elif sig.tranco_rank <= 1_000_000:
            benign += 10
    if sig.resolves is False:
        benign += 10

    breakdown = {
        "base": _BASE[category],
        "domain_risk": min(domain, 40),
        "content_risk": min(content, 30),
        "intel_hits": 20 if sig.intel_hit else 0,
        "benign_signals": -benign,
    }
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), category, breakdown)


@dataclass(frozen=True)
class UrlSignals:
    match: UrlMatch
    intel_hit: bool | None = None
    has_login_form: bool | None = None
    brand_in_content: bool | None = None


def score_url(sig: UrlSignals) -> Score:
    """共享托管平台等路径命中的 URL 按钓鱼网站评分，不给整个主机定性。"""
    m = sig.match
    if m.kind != "url":
        raise ValueError(f"只对 kind == 'url' 的 URL 评分（当前为 {m.kind}）")
    tokens = {r.token for r in m.path_reasons}
    url_brand = 15 + (
        5 if len(tokens) > 1 or any(r.where == "userinfo" for r in m.path_reasons) else 0
    )
    content = (15 if sig.has_login_form else 0) + (10 if sig.brand_in_content else 0)
    breakdown = {
        "base": _BASE[Category.PHISHING_SITE],
        "url_brand": url_brand,
        "content_risk": min(content, 30),
        "intel_hits": 20 if sig.intel_hit else 0,
    }
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), Category.PHISHING_SITE, breakdown)


SIGNALS = ("reported", "canary", "hotlink", "dmarc_fail")
SIGNAL_POINTS = {"reported": 15, "canary": 30, "hotlink": 15, "dmarc_fail": 15}
_SIGNAL_CATEGORY = {
    "reported": Category.REPORTED_PHISHING,
    "canary": Category.CLONE_SITE,
    "hotlink": Category.CLONE_SITE,
    "dmarc_fail": Category.EMAIL_SPOOFING,
}
_SIGNAL_BASE = {"reported": 45, "canary": 50, "hotlink": 40, "dmarc_fail": 40}


@dataclass(frozen=True)
class SignalFacts:
    signal: str
    volume: int = 0  # 盗链次数、DMARC 失败邮件数等
    intel_hit: bool = False
    has_login_form: bool | None = None
    brand_in_content: bool | None = None


def score_signal(f: SignalFacts) -> Score:
    """机构自有数据产生、但与品牌规则不匹配的指标（设计文档 4.12）。"""
    if f.signal not in _SIGNAL_CATEGORY:
        raise ValueError(f"未知自有信号：{f.signal}")
    volume = 20 if f.volume >= 100 else 10 if f.volume >= 10 else 0
    content = (15 if f.has_login_form else 0) + (10 if f.brand_in_content else 0)
    breakdown = {
        "base": _SIGNAL_BASE[f.signal],
        "owned_signal": SIGNAL_POINTS[f.signal],
        "volume": volume,
        "content_risk": min(content, 30),
        # 金丝雀本身就是确认（由 owned_signal 体现），不重复计入情报命中
        "intel_hits": 20 if f.intel_hit and f.signal != "canary" else 0,
    }
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), _SIGNAL_CATEGORY[f.signal], breakdown)


def with_signal(score: Score, signal: str) -> Score:
    """与品牌规则匹配的指标：在原评分上加自有信号因子。"""
    if signal not in SIGNAL_POINTS:
        raise ValueError(f"未知自有信号：{signal}")
    breakdown = {**score.breakdown, "owned_signal": SIGNAL_POINTS[signal]}
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), score.category, breakdown)


PASSWORD_CLASSES = frozenset({"Passwords"})
SECRET_LIKE_CLASSES = frozenset({"Password hints", "Security questions and answers", "Auth tokens"})


@dataclass(frozen=True)
class ExposureFacts:
    kind: str  # breach（公开泄露事件）/ stealer（窃密木马）
    affected: int  # 受影响的本机构账户数
    data_classes: frozenset[str] = frozenset()
    age_days: int | None = None  # 距泄露发生（或最近一次感染）的天数；None 表示未知
    verified: bool = True
    fabricated: bool = False
    spam_list: bool = False


def _credential_risk(f: ExposureFacts) -> int:
    if f.kind == "stealer" or f.data_classes & PASSWORD_CLASSES:
        return 25  # 窃密木马同时窃取口令与会话 Cookie
    return 10 if f.data_classes & SECRET_LIKE_CLASSES else 0


def _recency(age_days: int | None) -> int:
    if age_days is None:
        return 0
    if age_days <= 365:
        return 15
    if age_days <= 3 * 365:
        return 5
    return -10 if age_days > 5 * 365 else 0


def score_exposure(f: ExposureFacts) -> Score:
    """凭据暴露（设计文档 4.6、9.1）：是否含口令、发生多久、影响多少人、事件是否可信。"""
    breakdown = {
        "base": 45 if f.kind == "stealer" else 30,
        "credential_risk": _credential_risk(f),
        "recency": _recency(f.age_days),
        "scale": 15
        if f.affected >= 50
        else 10
        if f.affected >= 10
        else 5
        if f.affected >= 1
        else 0,
        "source_quality": -40 if f.fabricated else -20 if f.spam_list else 0 if f.verified else -10,
    }
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), Category.CREDENTIAL_EXPOSURE, breakdown)


def exposure_reasons(f: ExposureFacts) -> list[str]:
    reasons = []
    if f.kind == "stealer":
        reasons.append("infostealer")
    elif f.data_classes & PASSWORD_CLASSES:
        reasons.append("passwords_exposed")
    if f.age_days is not None and f.age_days <= 365:
        reasons.append("recent_breach")
    if f.affected >= 10:
        reasons.append("many_accounts")
    return reasons or ["credential_exposure"]


PARTY_BASE = {"self": 70, "critical": 55, "high": 45, "normal": 35}


@dataclass(frozen=True)
class RansomFacts:
    party: str
    how: str
    age_days: int | None


def score_ransomware(f: RansomFacts) -> Score:
    recency = 0
    if f.age_days is not None:
        recency = 10 if f.age_days <= 30 else -15 if f.age_days > 180 else 0
    breakdown = {
        "base": PARTY_BASE[f.party],
        "match_strength": 15 if f.how == "domain" else 5,
        "recency": recency,
    }
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), Category.RANSOMWARE_MENTION, breakdown)


@dataclass(frozen=True)
class CodeFacts:
    hits: int
    sensitive_paths: int
    internal_terms: bool
    critical_secrets: int
    other_secrets: int
    secret_in_hit_file: bool
    newest_secret_age_days: int | None


def score_code(f: CodeFacts) -> Score:
    """Score a related public repository without testing any found credential."""
    if f.critical_secrets + f.other_secrets == 0:
        breakdown = {
            "base": 15,
            "sensitive_path": 20 if f.sensitive_paths else 0,
            "internal_terms": 20 if f.internal_terms else 0,
            "scale": 5 if f.hits >= 5 else 0,
        }
        category = Category.DATA_LEAK
    else:
        age = f.newest_secret_age_days
        breakdown = {
            "base": 45,
            "secret_kind": 25 if f.critical_secrets else 10,
            "relevance": 20 if f.secret_in_hit_file else 10 if f.internal_terms else 0,
            "recency": 0 if age is None else 10 if age <= 90 else -10 if age > 730 else 0,
        }
        category = Category.SECRET_LEAK
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), category, breakdown)


def code_reasons(f: CodeFacts) -> list[str]:
    reasons = []
    if f.critical_secrets:
        reasons.append("secret_critical")
    elif f.other_secrets:
        reasons.append("secret_generic")
    if f.secret_in_hit_file:
        reasons.append("secret_in_brand_file")
    if not (f.critical_secrets or f.other_secrets):
        if f.sensitive_paths:
            reasons.append("sensitive_path")
        if f.internal_terms:
            reasons.append("internal_term")
    return reasons or ["code_mention"]


_TEXT_BASE = {"mention": 10, "press": 35, "fraud": 45, "intel": 40}
_TEXT_CATEGORY = {
    "mention": Category.BRAND_MENTION,
    "press": Category.NEGATIVE_PRESS,
    "fraud": Category.FRAUD_SCAM,
    "intel": Category.THREAT_INTEL,
}


@dataclass(frozen=True)
class TextFacts:
    kind: str  # mention / press / fraud / intel
    strong: bool
    boosters: int
    age_days: int | None
    reprints: int


def score_text(f: TextFacts) -> Score:
    """Score a news or web document by match strength, context and spread."""
    cap = 30 if f.kind == "fraud" else 20 if f.kind == "press" else 0
    breakdown = {
        "base": _TEXT_BASE[f.kind],
        "match_strength": 15 if f.strong else 5,
        "boosters": min(f.boosters * 10, cap),
        "recency": -10 if f.age_days is not None and f.age_days > 7 else 0,
        "spread": 5 if f.reprints >= 5 else 0,
    }
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), _TEXT_CATEGORY[f.kind], breakdown)


def text_reasons(f: TextFacts) -> list[str]:
    reasons = ["brand_name" if f.strong else "brand_abbreviation"]
    if f.kind == "fraud":
        reasons.append("fraud_terms")
    elif f.kind == "press":
        reasons.append("press_terms")
    elif f.kind == "intel":
        reasons.append("threat_report")
    if f.age_days is not None and f.age_days > 7:
        reasons.append("old_article")
    if f.reprints >= 5:
        reasons.append("widely_reprinted")
    return reasons


AVATAR_DISTANCE = 8  # dHash 汉明距离不超过它视为头像相似
NEW_ACCOUNT_DAYS = 30
_ACCOUNT_POINTS = {
    "display_same": 20,
    "display_similar": 10,
    "handle_same": 15,
    "handle_contains": 8,
    "avatar": 40,
    "bio_claim": 10,
    "new_account": 10,
}

ACCOUNT_SIGNALS = tuple(_ACCOUNT_POINTS)  # 页面与接口展示信号的固定顺序


@dataclass(frozen=True)
class AccountFacts:
    display: str | None = None  # same / similar
    handle: str | None = None  # same / contains
    avatar_distance: int | None = None
    bio_claim: bool = False
    age_days: int | None = None

    @property
    def named(self) -> bool:
        """显示名或账号名相似：没有名称信号的搜索结果直接丢弃。"""
        return self.display is not None or self.handle is not None


def score_account(f: AccountFacts) -> Score:
    """冒充社交账号：各信号只取较高一档，相加后按通用阈值分级。"""
    hits = [
        f"display_{f.display}" if f.display else None,
        f"handle_{f.handle}" if f.handle else None,
        "avatar"
        if f.avatar_distance is not None and f.avatar_distance <= AVATAR_DISTANCE
        else None,
        "bio_claim" if f.bio_claim else None,
        "new_account" if f.age_days is not None and f.age_days <= NEW_ACCOUNT_DAYS else None,
    ]
    breakdown = {hit: _ACCOUNT_POINTS[hit] for hit in hits if hit}
    value = min(100, sum(breakdown.values()))
    return Score(value, severity_for(value), Category.IMPERSONATION_ACCOUNT, breakdown)


SOFTWARE_TIER = {"critical": 20, "high": 10, "normal": 0}


@dataclass(frozen=True)
class VulnFacts:
    tier: str
    exposed: bool
    ransomware: bool
    age_days: int


def score_vulnerability(f: VulnFacts) -> Score:
    breakdown = {
        "base": 35,
        "asset_tier": SOFTWARE_TIER[f.tier],
        "exposure": 10 if f.exposed else 0,
        "ransomware": 10 if f.ransomware else 0,
        "recency": 10 if f.age_days <= 30 else -15 if f.age_days > 365 else 0,
    }
    value = max(0, min(100, sum(breakdown.values())))
    return Score(value, severity_for(value), Category.VULNERABILITY, breakdown)


def vuln_reasons(f: VulnFacts) -> list[str]:
    reasons = [f"{f.tier}_software" if f.tier != "normal" else "inventory_software"]
    if f.exposed:
        reasons.append("internet_facing")
    if f.ransomware:
        reasons.append("ransomware_use")
    if f.age_days <= 30:
        reasons.append("recently_added")
    elif f.age_days > 365:
        reasons.append("old_entry")
    return reasons
