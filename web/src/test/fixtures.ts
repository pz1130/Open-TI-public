import type { Schemas } from "../api/client";

export const ME_ANALYST: Schemas["Me"] = {
  auth_source: "local", must_change_password: false,
  username: "alice",
  display_name: "Alice Analyst",
  roles: ["analyst"],
  permissions: [
    "takedown:read", "takedown:draft", "tickets:read", "tickets:push",
    "alerts:read", "alerts:triage", "evidence:read", "rules:test",
    "suppressions:read", "suppressions:write", "watchlist:read", "certificates:read", "watchlist:write", "certificates:write", "documents:read", "reports:read", "connectors:read",
  ],
};

export const ME_VIEWER: Schemas["Me"] = {
  auth_source: "local", must_change_password: false,
  username: "vic",
  display_name: "",
  roles: ["viewer"],
  permissions: ["alerts:read", "watchlist:read", "certificates:read", "documents:read", "reports:read"],
};


export const ME_ADMIN: Schemas["Me"] = {
  auth_source: "local", must_change_password: false,
  username: "ops",
  display_name: "",
  roles: ["platform_admin"],
  permissions: ["certificates:approve", "certificates:read", "certificates:write", "connectors:read", "connectors:write", "dashboard:default"],
};



export const ALERT_SUMMARY: Schemas["AlertSummary"] = {
  ignored: false, ignored_at: null,
  id: 7, severity: "high", status: "open", category: "typosquat_domain", domain: "sbr-loans.com",
  score: 70, reasons: ["brand_label", "fraud_affix"], created_at: "2026-10-02T08:00:00Z",
  attack_techniques: [{ id: "T1583.001", name: "Domains", tactics: ["resource-development"], url: "https://attack.mitre.org/techniques/T1583/001/" }],
  notified_at: "2026-10-02T08:00:05Z", evidence_status: "done", screenshot_id: 11,
  triage_verdict: null, finding_id: 3, first_seen: "2026-10-01T00:00:00Z",
  last_seen: "2026-10-02T08:00:00Z", sources: ["certstream"],
};

export const ALERT_DETAIL: Schemas["AlertDetail"] = {
  takedowns: [],
  ticket: { ref: null, status: null, pushed_at: null, synced_at: null, available: false },
  alert: ALERT_SUMMARY,
  finding: {
    id: 3, category: "typosquat_domain", score: 70, severity: "high", status: "new",
    score_breakdown: { base: 20, domain_risk: 40, content_risk: 10, intel_hits: 0, benign_signals: 0 },
    match: { domain: "sbr-loans.com", registered: "sbr-loans.com", status: "match",
             reasons: [{ reason: "brand_label", token: "sbr", label: "sbr-loans", where: "registered", detail: "" }] },
    first_seen: "2026-10-01T00:00:00Z", last_seen: "2026-10-02T08:00:00Z", sources: ["certstream"],
  },
  enrichment: { dns: { data: { exists: true, a: ["203.0.113.5"] }, fetched_at: "2026-10-02T08:00:01Z" } },
  observations: [{ connector_id: "certstream", observed_at: "2026-10-02T08:00:00Z", score: 70 }],
  evidence: [
    { id: 11, kind: "screenshot", content_type: "image/png", sha256: "a".repeat(64), size: 1234,
      captured_at: "2026-10-02T08:01:00Z", node_id: "hk1", method: "opti-sandbox/0.1.0 (chromium 140)", source_url: "https://sbr-loans.com/" },
    { id: 12, kind: "html", content_type: "text/html", sha256: "b".repeat(64), size: 99,
      captured_at: "2026-10-02T08:01:00Z", node_id: "hk1", method: "opti-sandbox/0.1.0 (chromium 140)", source_url: "https://sbr-loans.com/" },
  ],
  feedback: [],
  history: [],
  related_alerts: [],
  campaign: null,
  watch: null,
  assignee: null,
  entity_type: "domain",
  translation_available: false,
};


export const ME_RESPONDER: Schemas["Me"] = {
  auth_source: "local", must_change_password: false,
  username: "carol",
  display_name: "",
  roles: ["responder"],
  permissions: [
    "alerts:read", "evidence:read", "watchlist:read", "certificates:read", "suppressions:read",
    "takedown:read", "takedown:draft", "takedown:approve", "tickets:push", "evidence:export", "blocklist:export", "exposure:accounts", "documents:read", "reports:read",
  ],
};

export const TARGET: Schemas["TargetOut"] = {
  kind: "registrar", id: "registrar:cheap", name: "Cheap Registrar LLC", email: "abuse@registrar.example",
  url: null, basis: "rdap_registrar", detail: "", note: "",
};

export const TAKEDOWN: Schemas["TakedownOut"] = {
  id: 5, alert_id: 7, domain: "sbr-loans.com", target: TARGET, language: "zh-CN",
  subject: "滥用投诉：sbr-loans[.]com", body: "正文\n", state: "draft", created_by: "bob", approved_by: null,
  external_ref: null, created_at: "2026-10-03T00:00:00Z", updated_at: "2026-10-03T00:00:00Z",
  submitted_at: null, resolved_at: null, due_at: null, reminders: 0, reappeared_alert_id: null,
};

export const EXPOSURE: Schemas["ExposureOut"] = {
  source: "hibp", kind: "breach", domain: "sbr.int", title: "New Leak 2026", breach_date: "2026-08-01",
  added_date: "2026-10-01T00:00:00Z", data_classes: ["Email addresses", "Passwords"], verified: true,
  fabricated: false, sensitive: false, spam_list: false, stealer_log: false, affected: 2,
  accounts_total: 2, accounts_pending: 2, can_push: true,
};

export const REPORT_DETAIL = {
  id: 3,
  kind: "daily",
  title: "威胁情报日报 2026-10-03",
  period_start: "2026-10-02T01:00:00Z",
  period_end: "2026-10-03T01:00:00Z",
  created_at: "2026-10-03T01:00:05Z",
  sent_at: "2026-10-03T01:00:09Z",
  totals: { findings: 6, alerts: 3, critical: 0, high: 1, medium: 2, low: 3 },
  content: {
    kind: "daily",
    totals: { findings: 6, alerts: 3, critical: 0, high: 1, medium: 2, low: 3 },
    by_category: [{ category: "typosquat_domain", findings: 2, alerts: 1 }],
    alerts: [{ alert_id: 7, severity: "medium", category: "typosquat_domain", subject: "sbr-portal.top", score: 50 }],
    news: [{ finding_id: 9, alert_id: null, category: "brand_mention", title: "Bank approves loan", url: "https://news.example/a", source: "Example News", summary: "批准贷款", score: 25 }],
    vulnerabilities: [{ finding_id: 11, alert_id: 8, cve: "CVE-2026-12345", name: "EdgeGate VPN Bypass", software: ["Example Networks EdgeGate VPN"], severity: "medium", score: 55 }],
  },
};

export const MONTHLY_REPORT = {
  id: 5,
  kind: "monthly",
  title: "威胁情报月报 2026-09",
  period_start: "2026-08-31T16:00:00Z",
  period_end: "2026-09-30T16:00:00Z",
  created_at: "2026-10-01T01:10:05Z",
  sent_at: null,
  totals: { findings: 8, alerts: 4, critical: 1, high: 1, medium: 2, low: 4 },
  content: {
    kind: "monthly",
    totals: { findings: 8, alerts: 4, critical: 1, high: 1, medium: 2, low: 4 },
    previous: { findings: 9, alerts: 1, critical: 0, high: 1, medium: 0, low: 0 },
    by_category: [{ category: "typosquat_domain", alerts: 2, previous: 0 }],
    alerts: [
      { alert_id: 7, severity: "high", category: "typosquat_domain", subject: "sbr-old.top", score: 70, status: "closed", verdict: "true_positive", takedown: "submitted" },
      { alert_id: 8, severity: "critical", category: "phishing_site", subject: "sbr-pay.top", score: 90, status: "open", verdict: null, takedown: null },
    ],
    news: [{ finding_id: 9, alert_id: null, category: "negative_press", title: "SBR fined", url: "https://news.example/a", source: "Example News", summary: "", score: 30 }],
    vulnerabilities: [],
    counts: { news: 12, vulnerabilities: 0 },
    trend: [
      { month: "2026-08", critical: 0, high: 1, medium: 0 },
      { month: "2026-09", critical: 1, high: 1, medium: 2 },
    ],
  },
};

export const EMPTY_DASHBOARD = {
  days: 30,
  generated_at: "2026-10-03T08:00:00Z",
  open_alerts: { critical: 0, high: 0, medium: 0, low: 0 },
  new_alerts: 0,
  new_findings: 0,
  trend: [{ day: "2026-10-03", critical: 0, high: 0, medium: 0, low: 0 }],
  by_category: [],
  by_source: [],
  mttd: [
    { source: "ct", count: 0, median_hours: null, within_target: null, target_hours: 1 },
    { source: "nrd", count: 0, median_hours: null, within_target: null, target_hours: 24 },
  ],
  mttr_hours: null,
  overdue: { critical: 0, high: 0, medium: 0 },
  overdue_alerts: [],
  top_alerts: [],
  hosting_countries: [],
  hosting_networks: [],
};

export const DASHBOARD = {
  ...EMPTY_DASHBOARD,
  open_alerts: { critical: 1, high: 2, medium: 3, low: 0 },
  new_alerts: 6,
  new_findings: 9,
  trend: [
    { day: "2026-10-02", critical: 1, high: 1, medium: 0, low: 0 },
    { day: "2026-10-03", critical: 0, high: 1, medium: 3, low: 0 },
  ],
  by_category: [{ name: "typosquat_domain", count: 4 }, { name: "phishing_site", count: 2 }],
  by_source: [{ name: "certstream", count: 7 }],
  mttd: [
    { source: "ct", count: 2, median_hours: 0.5, within_target: 1, target_hours: 1 },
    { source: "nrd", count: 1, median_hours: 30, within_target: 0, target_hours: 24 },
  ],
  mttr_hours: 20.5,
  overdue: { critical: 0, high: 1, medium: 0 },
  overdue_alerts: [{ alert_id: 7, severity: "high", category: "typosquat_domain", subject: "sbr-loans.com", score: 72, created_at: "2026-10-02T02:00:00Z", overdue_hours: 6 }],
  top_alerts: [{ alert_id: 9, severity: "critical", category: "phishing_site", subject: "https://sbr-pay.top/login", score: 91, created_at: "2026-10-03T06:00:00Z", overdue_hours: null }],
  hosting_countries: [{ name: "NL", count: 3 }],
  hosting_networks: [{ name: "EXAMPLE-NET", count: 2 }],
};


export const CONNECTORS = [
  {
    id: "crtsh", name: "crt.sh", category: "ct", tier: "free", kind: ["poll"], egress: "overseas",
    homepage: "https://crt.sh", tos_url: null, commercial_use: "allowed", last_reviewed: "2026-10-01", pii_risk: "low",
    compliance_notes: "公开 CT 日志", schedule: "*/30 * * * *", enabled: true, license_approved: true,
    license_ref: "CT-PUBLIC", plan: "free", runnable: true, reason: "ok", location: "node:hk1", credentials: [],
    health: "failing",
    last_run: { started_at: "2026-10-03T07:00:00Z", ended_at: "2026-10-03T07:01:00Z", status: "error", items: 0, errors: 1, message: "HttpError: 503", node_id: "hk1" },
    last_success_at: "2026-10-02T07:00:00Z", runs_24h: 3, errors_24h: 1,
  },
  {
    id: "urlscan", name: "urlscan.io", category: "phishing", tier: "freemium", kind: ["poll"], egress: "overseas",
    homepage: "https://urlscan.io", tos_url: "https://urlscan.io/terms/", commercial_use: "restricted", last_reviewed: null,
    pii_risk: "low", compliance_notes: "", schedule: null, enabled: true, license_approved: false, license_ref: null,
    plan: "free", runnable: null, reason: "waiting_for_node：等待采集节点上报", location: "collector",
    credentials: [{ name: "api_key", required: false, configured: null }], health: "unknown",
    last_run: null, last_success_at: null, runs_24h: 0, errors_24h: 0,
  },
];


export const ME_LLM_ADMIN: Schemas["Me"] = { ...ME_ADMIN, permissions: [...ME_ADMIN.permissions, "llm:read", "llm:admin"] };
export const ME_AUDITOR: Schemas["Me"] = {
  auth_source: "local", must_change_password: false, username: "aud", display_name: "", roles: ["auditor"], permissions: ["audit:read", "llm:read"],
};

export const LLM_PRESETS: Schemas["LlmPresetOut"][] = [
  { key: "openai", name: "OpenAI", group: "international", protocol: "openai", auth: "bearer", base_url: "https://api.openai.com/v1",
    model: "gpt-5-mini", json_mode: true, temperature: null, list_models: "yes", key_required: true, insecure_http: false },
  { key: "deepseek", name: "DeepSeek", group: "domestic", protocol: "openai", auth: "bearer", base_url: "https://api.deepseek.com/v1",
    model: "deepseek-flash", json_mode: true, temperature: 0, list_models: "yes", key_required: true, insecure_http: false },
  { key: "minimax", name: "MiniMax", group: "domestic", protocol: "anthropic", auth: "bearer", base_url: "https://api.minimax.cn/anthropic/v1",
    model: "MiniMax-M2", json_mode: false, temperature: 1, list_models: "no", key_required: true, insecure_http: false },
  { key: "selfhosted", name: "自托管（vLLM / Ollama）", group: "local", protocol: "openai", auth: "bearer", base_url: "",
    model: "", json_mode: true, temperature: 0, list_models: "yes", key_required: false, insecure_http: true },
];

export const LLM_PROVIDER: Schemas["LlmProviderOut"] = {
  id: 1, name: "DeepSeek", preset: "deepseek", group: "domestic", base_url: "https://api.deepseek.com/v1", model: "deepseek-flash",
  api_key_set: true, api_key_hint: "abcd", proxy_hint: null, json_mode: true, temperature: 0, timeout_seconds: 60,
  last_test_at: null, last_test_ok: null, last_test_error: null, in_use: null, updated_at: "2026-10-10T08:00:00Z",
};

export const LLM_SETTINGS: Schemas["LlmSettingsOut"] = {
  enabled: false, primary_id: null, backup_id: null, gray_zone_low: 30, gray_zone_high: 70, max_per_run: 20,
  max_attempts: 3, max_wait_minutes: 30, summary_language: "Chinese", code_enabled: false, updated_at: null,
};

export const LLM_STATUS: Schemas["LlmStatusOut"] = {
  encryption_key: true, problem: null, queue: 0, done_24h: 0, failed_24h: 0, worker_problem: null, worker_checked_at: null,
};

export const ME_CONFIG_ANALYST: Schemas["Me"] = { ...ME_ANALYST, permissions: [...ME_ANALYST.permissions, "config:read", "rules:write"] };
export const ME_CONFIG_VIEWER: Schemas["Me"] = { ...ME_VIEWER, permissions: [...ME_VIEWER.permissions, "config:read"] };
export const ME_CONFIG_ADMIN: Schemas["Me"] = { ...ME_ADMIN, permissions: [...ME_ADMIN.permissions, "config:read", "config:write", "organization:write", "projects:write", "users:write", "access:write"] };

export const CONFIG_RULES: Schemas["ConfigOut"] = {
  kind: "rules", version: 3, source: "db", file_path: null,
  yaml: "project: sbr\nauthorization_ref: SBR-1\n",
  data: {
    project: "sbr", authorization_ref: "SBR-1", languages: ["en"],
    sets: { brand: { weight: 1, role: "match", type: "brand", approval_ref: null, category: null, private: false,
      terms: [{ value: "Sample Brand", mode: "phrase", case_sensitive: false, remote_search: true, variants: null, require_any_within: null }] } },
    domains: { official: ["sbr.int"], known_lookalikes: [], brand_tokens: ["sbr"], combo_affixes: [], fraud_affixes: [], restricted_tokens: {}, short_token_max_len: 4 },
  },
  digest: "r3", created_by: "alice", created_at: "2026-10-12T08:00:00Z", note: "加中文品牌词", restored_from: null,
};

export const CONFIG_ORG: Schemas["ConfigOut"] = {
  kind: "organization", version: 0, source: "file", file_path: "config/organization.yaml",
  yaml: "name: Example Organization\n",
  data: { name: "Example Organization", short_name: "Example", website: null, security_contact: null,
    legal_statement: "", legal_statement_en: "", takedown_sender: null, signature: "" },
  digest: "o0", created_by: null, created_at: null, note: null, restored_from: null,
};

export const CONFIG_RETENTION: Schemas["ConfigOut"] = {
  kind: "retention", version: 0, source: "file", file_path: "config/retention.yaml", yaml: "cases_days: 1095\n",
  data: { raw_items_days: 90, report_contacts_days: 90, exposed_accounts_days: 180, documents_days: 365,
    findings_days: 365, cases_days: 1095, connector_runs_days: 90, reports_days: 365 },
  digest: "rt0", created_by: null, created_at: null, note: null, restored_from: null,
};

export const CONFIG_CAMPAIGNS: Schemas["ConfigOut"] = {
  kind: "campaigns", version: 0, source: "file", file_path: "config/campaigns.yaml", yaml: "max_share: 10\n",
  data: { window_days: 30, max_share: 10, min_members: 2, signals: ["tls_sha256", "ip"] },
  digest: "ca0", created_by: null, created_at: null, note: null, restored_from: null,
};

export const CONFIG_TAKEDOWN: Schemas["ConfigOut"] = {
  kind: "takedown", version: 0, source: "file", file_path: "config/takedown/platforms.yaml", yaml: "sla_hours:\n  hosting: 48\n",
  data: {
    sla_hours: { registrar: 72, hosting: 48, cdn: 48, report: 0, platform: 72 }, max_reminders: 3,
    providers: [{ id: "cloudflare", name: "Cloudflare", nameservers: [".ns.cloudflare.com"], network_names: ["CLOUDFLARENET"], orgs: [],
      channel: { email: null, url: "https://abuse.cloudflare.com/phishing" }, note: "" }],
    reporting: [{ id: "netcraft", name: "Netcraft", tlds: [], channel: { email: null, url: "https://report.netcraft.com/report" }, note: "" }],
    platforms: [{ id: "linkedin", name: "LinkedIn", hosts: ["linkedin.com", "lnkd.in"], channel: null, note: "" }],
    escalation: [],
  },
  digest: "k0", created_by: null, created_at: null, note: null, restored_from: null, builtin: null,
};

const TPL = { registrar: "Subject: 当前\n正文", hosting: "Subject: h\n", cdn: "Subject: c\n", report: "Subject: r\n", platform: "Subject: p\n" };
export const CONFIG_TEMPLATES: Schemas["ConfigOut"] = {
  kind: "takedown_templates", version: 0, source: "file", file_path: "config/takedown/templates", yaml: "",
  data: { "zh-CN": TPL, "en-US": TPL },
  builtin: { "zh-CN": { ...TPL, registrar: "Subject: 内置\n正文" }, "en-US": TPL },
  digest: "tp0", created_by: null, created_at: null, note: null, restored_from: null,
};

export const CONFIG_TICKETS: Schemas["ConfigOut"] = {
  kind: "tickets", version: 0, source: "file", file_path: "config/tickets.yaml", yaml: "",
  data: { enabled: true, mode: "webhook", auto_push: [], id_field: "ticket_id", email_to: [], status_map: { resolved: "closed" } },
  digest: "tk0", created_by: null, created_at: null, note: null, restored_from: null, builtin: null,
};

export const CONFIG_VENDORS: Schemas["ConfigOut"] = {
  kind: "vendors", version: 1, source: "db", file_path: null, yaml: "",
  data: { vendors: [{ id: "example-cloud", name: "Example Cloud Services Ltd", aliases: ["Example Cloud"], domains: ["example-cloud.example"], tier: "critical", owner: "IT" }] },
  digest: "v1", created_by: "ops", created_at: "2026-10-12T08:00:00Z", note: null, restored_from: null, builtin: null,
};

export const CONFIG_SOFTWARE: Schemas["ConfigOut"] = {
  kind: "software", version: 1, source: "db", file_path: null, yaml: "",
  data: { software: [{ id: "vpn", vendor: "Fortinet", vendor_aliases: [], products: ["FortiOS"], tier: "critical", exposed: true, owner: "网络组" }] },
  digest: "s1", created_by: "ops", created_at: "2026-10-12T08:00:00Z", note: null, restored_from: null, builtin: null,
};

export const CONFIG_SHARING: Schemas["ConfigOut"] = {
  kind: "sharing", version: 0, source: "file", file_path: "config/sharing.yaml", yaml: "",
  data: {
    stix: { tlp: "amber", min_severity: "medium" },
    siem: { min_severity: "medium", categories: [],
      syslog: { enabled: true, host: "siem.example.org", port: 6514, protocol: "tls", ca_file: "", ca_pem: "", app_name: "opti" },
      webhook: { enabled: false, url: "", format: "json", token_header: "Authorization", token_prefix: "", timeout_seconds: 10 } },
  },
  digest: "sh0", created_by: null, created_at: null, note: null, restored_from: null, builtin: null,
};

export const CONFIG_STATUS: Schemas["ConfigStatusOut"] = {
  current: { rules: 3, organization: 0 },
  current_digest: { rules: "r3", organization: "o0" },
  processes: [
    { process: "api@h", kind: "rules", version: 3, digest: "r3", error: null, updated_at: "2026-10-12T08:00:05Z", stale: false, edge: false },
    { process: "worker@h", kind: "rules", version: 2, digest: "r2", error: null, updated_at: "2026-10-12T08:00:01Z", stale: false, edge: false },
    { process: "stream-certstream@h", kind: "rules", version: 2, digest: "r2", error: "v3: 无效", updated_at: "2026-10-12T08:00:01Z", stale: false, edge: false },
    { process: "intake@e", kind: "rules", version: 1, digest: "r1", error: null, updated_at: "2026-10-11T08:00:00Z", stale: true, edge: true },
  ],
};

export const ME_ALERTING_ADMIN: Schemas["Me"] = { ...ME_CONFIG_ADMIN, permissions: [...ME_CONFIG_ADMIN.permissions, "alerting:write"] };

export const CONFIG_ALERTING: Schemas["ConfigOut"] = {
  kind: "alerting", version: 2, source: "db", file_path: null, yaml: "channels: []\n",
  data: {
    public_base_url: "https://ti.example", digest: ["medium"], report_language: "zh-CN", report_timezone: "Asia/Shanghai",
    smtp: { host: "relay", port: 25, starttls: true, sender: "ti@example.org" },
    channels: [{ id: "secops", name: "安全值班", type: "teams", enabled: true, severities: ["critical", "high"],
      categories: [], reports: ["daily"], notices: true, recipients: [] }],
  },
  digest: "a2", created_by: "ops", created_at: "2026-10-12T08:00:00Z", note: null, restored_from: null,
};

export const ALERTING_SECRETS: Schemas["ConfigSecretsOut"] = {
  encryption_key: true,
  secrets: [
    { name: "channel:secops:webhook_url", set: true, hint: "1234", source: "db", updated_by: "ops", updated_at: "2026-10-12T08:00:00Z" },
    { name: "smtp_password", set: true, hint: null, source: "env", updated_by: null, updated_at: null },
    { name: "smtp_username", set: false, hint: null, source: "none", updated_by: null, updated_at: null },
  ],
};
