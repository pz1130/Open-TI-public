import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, unwrap, type Schemas } from "./client";
import { requestWatchCheck } from "./watchChecks";

export type Me = Schemas["Me"];
export type LlmPreset = Schemas["LlmPresetOut"];
export type LlmProvider = Schemas["LlmProviderOut"];
export type LlmSettings = Schemas["LlmSettingsOut"];

export type AlertFilters = { status: string[]; severity: string[]; category?: string; q?: string; ignored?: "exclude" | "only" | "all" };
export type DocumentFilters = { q: string; language?: string };
export type ReportKind = "" | "daily" | "weekly" | "monthly";
export type CampaignState = "candidate" | "confirmed" | "dismissed";
export type DashboardQuery = { days: number; category?: string | null; limit?: number };
export type LayoutSpec = Schemas["LayoutSpec"];
export type ConfigKind = "rules" | "organization" | "alerting" | "retention" | "campaigns" | "takedown" | "takedown_templates" | "tickets" | "vendors" | "software" | "sharing" | "connectors" | "identity" | "operations";
export type ConfigOut = Schemas["ConfigOut"];
export type ConfigStatus = Schemas["ConfigStatusOut"];
export type ConfigProcess = Schemas["ConfigProcessOut"];
export type ConfigError = Schemas["ConfigErrorOut"];
export type ConfigRevision = Schemas["ConfigRevisionOut"];
type ConfirmFields = "confirm_project_change" | "confirm_oidc_change" | "confirm_retention";
export type ConfigSaveDraft = Omit<Schemas["ConfigSaveIn"], ConfirmFields> & Partial<Pick<Schemas["ConfigSaveIn"], ConfirmFields>>;

export const keys = {
  llmAll: ["llm"] as const,
  llmPresets: ["llm", "presets"] as const,
  llmStatus: ["llm", "status"] as const,
  llmSettings: ["llm", "settings"] as const,
  llmProviders: ["llm", "providers"] as const,
  connectors: ["connectors"] as const,
  dashboard: (q: DashboardQuery) => ["dashboard", q.days, q.category ?? null, q.limit ?? 10] as const,
  dashboardLayout: ["dashboard-layout"] as const,
  dashboardDefault: ["dashboard-layout-default"] as const,
  myAlerts: (limit: number) => ["alerts", "mine", limit] as const,
  documents: (filters: DocumentFilters) => ["documents", filters] as const,
  reports: (kind: ReportKind) => ["reports", kind] as const,
  report: (id: number) => ["report", id] as const,
  takedowns: (f: TakedownFilters) => ["takedowns", f] as const,
  takedownsAll: ["takedowns"] as const,
  takedown: (id: number) => ["takedown", id] as const,
  takedownStats: ["takedown-stats"] as const,
  targets: (alertId: number) => ["takedown-targets", alertId] as const,

  me: ["me"] as const,
  watchlist: (f: WatchFilters) => ["watchlist", f] as const,
  watchAll: ["watchlist"] as const,
  observations: (id: number) => ["observations", id] as const,
  domainKeywords: ["domain-keywords"] as const,
  keywordDomains: (kind: KeywordKind, value: string, page: number, pageSize: number) =>
    ["domain-keywords", kind, value, page, pageSize] as const,
  suppressions: (inactive: boolean) => ["suppressions", inactive] as const,
  suppressionsAll: ["suppressions"] as const,
  audit: (f: AuditFilters) => ["audit", f] as const,
  alerts: (f: AlertFilters) => ["alerts", f] as const,
  alertsAll: ["alerts"] as const,
  alert: (id: number) => ["alert", id] as const,
  exposure: (id: number) => ["exposure", id] as const,
  exposureAccounts: (id: number) => ["exposure-accounts", id] as const,
  campaigns: (state: CampaignState, page: number) => ["campaigns", state, page] as const,
  campaignsAll: ["campaigns"] as const,
  campaign: (id: number) => ["campaign", id] as const,
  configAll: ["config"] as const,
  config: (kind: ConfigKind) => ["config", kind] as const,
  configRevisions: (kind: ConfigKind) => ["config", kind, "revisions"] as const,
  configRevision: (kind: ConfigKind, v: number) => ["config", kind, "revision", v] as const,
  configStatus: ["config-status"] as const,
};


export function useMe() {
  return useQuery({
    queryKey: keys.me,
    queryFn: async (): Promise<Me | null> => {
      const r = await api.GET("/api/v1/auth/me");
      if (r.response.status === 401) return null;
      return unwrap(r);
    },
    retry: false,
    staleTime: 5 * 60_000,
    refetchInterval: 15_000,
  });
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Schemas["LoginRequest"]) => unwrap(await api.POST("/api/v1/auth/login", { body })),
    onSuccess: (me) => {
      qc.removeQueries({ predicate: (query) => query.queryKey[0] !== "me" });
      qc.setQueryData(keys.me, me);
    },
  });
}

/** 整页跳转（身份提供方登出、单点登录）；测试中可替换。 */
export const browser = {
  go(url: string): void {
    window.location.assign(url);
  },
};

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => unwrap(await api.POST("/api/v1/auth/logout")),
    onSuccess: (out) => {
      qc.removeQueries({ predicate: (query) => query.queryKey[0] !== "me" });
      qc.setQueryData(keys.me, null);
      if (out.logout_url) browser.go(out.logout_url); // 单点登录会话：同时结束身份提供方会话
    },
  });
}


export function useAuthProviders() {
  return useQuery({
    queryKey: ["auth-providers"],
    queryFn: async () => unwrap(await api.GET("/api/v1/auth/providers")),
    staleTime: Infinity,
    retry: false,
  });
}

export function oidcStartUrl(next: string): string {
  return `/api/v1/auth/oidc/start?next=${encodeURIComponent(next)}`;
}


export function useAlerts(f: AlertFilters, page = 1, pageSize = 20) {
  return useQuery({
    refetchInterval: 15_000,
    queryKey: [...keys.alerts(f), page, pageSize],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/alerts", {
          params: {
            query: {
              status: f.status.length ? f.status : undefined,
              severity: f.severity.length ? f.severity : undefined,
              category: f.category || undefined,
              q: f.q || undefined,
              ignored: f.ignored ?? "exclude",
              page, limit: pageSize,
            },
          },
        }),
      ),
  });
}

export function useDocuments(filters: DocumentFilters, page = 1, pageSize = 20) {
  return useQuery({
    queryKey: [...keys.documents(filters), page, pageSize],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/documents", {
          params: {
            query: {
              q: filters.q || undefined,
              language: filters.language || undefined,
              page, limit: pageSize,
            },
          },
        }),
      ),
  });
}

export function useAlert(id: number) {
  return useQuery({
    queryKey: keys.alert(id),
    queryFn: async () => unwrap(await api.GET("/api/v1/alerts/{alert_id}", { params: { path: { alert_id: id } } })),
    enabled: Number.isInteger(id) && id > 0,
  });
}

function useAlertMutation<B>(id: number, send: (body: B) => Promise<Schemas["AlertSummary"]>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: send,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.alert(id) });
      void qc.invalidateQueries({ queryKey: keys.alertsAll });
    },
  });
}

export function useUpdateAlert(id: number) {
  return useAlertMutation(id, async (body: Schemas["AlertUpdate"]) =>
    unwrap(await api.PATCH("/api/v1/alerts/{alert_id}", { params: { path: { alert_id: id } }, body })),
  );
}

export function useIgnoreAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ignored }: { id: number; ignored: boolean }) => unwrap(await api.PATCH(
      "/api/v1/alerts/{alert_id}", { params: { path: { alert_id: id } }, body: { ignored } },
    )),
    onSuccess: (_data, variables) => {
      void qc.invalidateQueries({ queryKey: keys.alertsAll });
      void qc.invalidateQueries({ queryKey: keys.alert(variables.id) });
    },
  });
}

export function useSubmitFeedback(id: number) {
  return useAlertMutation(id, async (body: Schemas["FeedbackIn"]) =>
    unwrap(await api.POST("/api/v1/alerts/{alert_id}/feedback", { params: { path: { alert_id: id } }, body })),
  );
}

/** 证据走同源 Cookie 鉴权；HTML 快照由服务器以纯文本附件返回。 */
export function evidenceUrl(id: number): string {
  return `/api/v1/evidence/${id}/content`;
}


export type WatchFilters = { includeExpired: boolean; q?: string };
export type AuditFilters = { actor?: string; action?: string };

export function useWatchlist(f: WatchFilters, page = 1, pageSize = 20) {
  return useQuery({
    queryKey: [...keys.watchlist(f), page, pageSize],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/watchlist", {
          params: { query: { include_expired: f.includeExpired, q: f.q || undefined, page, limit: pageSize } },
        }),
      ),
  });
}

export function useWatchObservations(id: number | null, poll = false) {
  return useQuery({
    queryKey: keys.observations(id ?? 0),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/watchlist/{watch_id}/observations", { params: { path: { watch_id: id as number } } })),
    enabled: id !== null,
    refetchInterval: poll ? 5000 : false,
  });
}

export function useAddWatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Schemas["WatchIn"]) => unwrap(await api.POST("/api/v1/watchlist", { body })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.watchAll }),
  });
}

export function useUpdateWatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, body }: { id: number; body: Schemas["WatchIn"] }) =>
      unwrap(await api.PUT("/api/v1/watchlist/{watch_id}", { params: { path: { watch_id: id } }, body })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.watchAll }),
  });
}

export function useCheckWatch() {
  return useMutation({
    mutationFn: requestWatchCheck,
    retry: false,
  });
}

export function useRemoveWatch() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, reason }: { id: number; reason: string }) =>
      unwrap(await api.DELETE("/api/v1/watchlist/{watch_id}", { params: { path: { watch_id: id }, query: { reason } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.watchAll }),
  });
}

export type KeywordKind = Schemas["KeywordIn"]["kind"];
export type DomainKeywords = Schemas["DomainKeywordsOut"];
export type KeywordChange = Schemas["KeywordChangeOut"];

function useKeywordMutation<A>(fn: (arg: A) => Promise<KeywordChange>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.domainKeywords });
      void qc.invalidateQueries({ queryKey: keys.configAll });
    },
  });
}

export function useDomainKeywords() {
  return useQuery({
    queryKey: keys.domainKeywords,
    queryFn: async () => unwrap(await api.GET("/api/v1/watchlist/keywords")),
  });
}

export function useAddKeyword() {
  return useKeywordMutation(async (body: Schemas["KeywordIn"]) =>
    unwrap(await api.POST("/api/v1/watchlist/keywords", { body })));
}

export function useUpdateAffixes() {
  return useKeywordMutation(async ({ token, affixes }: { token: string; affixes: string[] }) =>
    unwrap(await api.PUT("/api/v1/watchlist/keywords/restricted/{token}", { params: { path: { token } }, body: { affixes } })));
}

export function useRemoveKeyword() {
  return useKeywordMutation(async ({ kind, value }: { kind: KeywordKind; value: string }) =>
    unwrap(await api.DELETE("/api/v1/watchlist/keywords/{kind}/{value}", { params: { path: { kind, value } } })));
}

export function useKeywordDomains(kind: KeywordKind, value: string | null, page: number, pageSize: number) {
  return useQuery({
    queryKey: keys.keywordDomains(kind, value ?? "", page, pageSize),
    enabled: value !== null,
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/watchlist/keywords/{kind}/{value}/domains", {
        params: { path: { kind, value: value ?? "" }, query: { page, limit: pageSize } },
      })),
  });
}

export function useKeywordBackfill() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => unwrap(await api.POST("/api/v1/watchlist/keywords/backfill")),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.domainKeywords }),
  });
}

export function useRulesTest() {
  return useMutation({
    mutationFn: async (body: Schemas["RulesTestIn"]) => unwrap(await api.POST("/api/v1/rules/test", { body })),
  });
}

export function useSuppressions(includeInactive: boolean) {
  return useQuery({
    queryKey: keys.suppressions(includeInactive),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/suppressions", { params: { query: { include_inactive: includeInactive } } })),
  });
}

export function useCreateSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Schemas["SuppressionIn"]) => unwrap(await api.POST("/api/v1/suppressions", { body })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.suppressionsAll }),
  });
}

export function useRevokeSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) =>
      unwrap(await api.DELETE("/api/v1/suppressions/{rule_id}", { params: { path: { rule_id: id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.suppressionsAll }),
  });
}

export function useAuditLogs(f: AuditFilters, page = 1, pageSize = 20) {
  return useQuery({
    queryKey: [...keys.audit(f), page, pageSize],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/audit-logs", {
          params: { query: { actor: f.actor || undefined, action: f.action || undefined, page, limit: pageSize } },
        }),
      ),
  });
}

export function useAuditVerify() {
  return useMutation({
    mutationFn: async () => unwrap(await api.GET("/api/v1/audit-logs/verify")),
  });
}


export type TakedownFilters = { state: string[] };

export function useTakedownTargets(alertId: number, enabled: boolean) {
  return useQuery({
    queryKey: keys.targets(alertId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/alerts/{alert_id}/takedown-targets", { params: { path: { alert_id: alertId } } })),
    enabled,
  });
}

export function useCreateTakedown(alertId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Schemas["TakedownIn"]) =>
      unwrap(await api.POST("/api/v1/alerts/{alert_id}/takedowns", { params: { path: { alert_id: alertId } }, body })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.alert(alertId) });
      void qc.invalidateQueries({ queryKey: keys.takedownsAll });
    },
  });
}

export function useTakedowns(f: TakedownFilters, page = 1, pageSize = 20) {
  return useQuery({
    queryKey: [...keys.takedowns(f), page, pageSize],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/takedowns", {
          params: { query: { state: f.state.length ? f.state : undefined, page, limit: pageSize } },
        }),
      ),
  });
}

export function useTakedown(id: number | null) {
  return useQuery({
    queryKey: keys.takedown(id ?? 0),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/takedowns/{takedown_id}", { params: { path: { takedown_id: id as number } } })),
    enabled: id !== null,
  });
}

export function useTakedownStats() {
  return useQuery({
    queryKey: keys.takedownStats,
    queryFn: async () => unwrap(await api.GET("/api/v1/takedowns/stats")),
  });
}

function useTakedownMutation<B>(id: number, send: (body: B) => Promise<Schemas["TakedownOut"]>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: send,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.takedown(id) });
      void qc.invalidateQueries({ queryKey: keys.takedownsAll });
      void qc.invalidateQueries({ queryKey: keys.takedownStats });
      void qc.invalidateQueries({ queryKey: ["alert"] });
    },
  });
}

export function useEditTakedown(id: number) {
  return useTakedownMutation(id, async (body: Schemas["TakedownEdit"]) =>
    unwrap(await api.PATCH("/api/v1/takedowns/{takedown_id}", { params: { path: { takedown_id: id } }, body })),
  );
}

export function useTransitionTakedown(id: number) {
  return useTakedownMutation(id, async (body: Schemas["TakedownTransition"]) =>
    unwrap(await api.POST("/api/v1/takedowns/{takedown_id}/transition", { params: { path: { takedown_id: id } }, body })),
  );
}

function useTicketMutation<B>(alertId: number, send: (body: B) => Promise<Schemas["TicketOut"]>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: send,
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.alert(alertId) }),
  });
}

export function usePushTicket(alertId: number) {
  return useTicketMutation(alertId, async (_: void) =>
    unwrap(await api.POST("/api/v1/alerts/{alert_id}/ticket", { params: { path: { alert_id: alertId } } })),
  );
}

export function useSetTicketRef(alertId: number) {
  return useTicketMutation(alertId, async (body: Schemas["TicketRefIn"]) =>
    unwrap(await api.PUT("/api/v1/alerts/{alert_id}/ticket", { params: { path: { alert_id: alertId } }, body })),
  );
}

/** .eml 与证据包走同源 Cookie 鉴权，直接作为下载链接。 */
export function takedownEmlUrl(id: number): string {
  return `/api/v1/takedowns/${id}/eml`;
}

export function evidenceBundleUrl(alertId: number): string {
  return `/api/v1/alerts/${alertId}/evidence-bundle`;
}

export function useExposure(alertId: number) {
  return useQuery({
    queryKey: keys.exposure(alertId),
    queryFn: async () => unwrap(await api.GET("/api/v1/alerts/{alert_id}/exposure", { params: { path: { alert_id: alertId } } })),
  });
}

/** 受影响账户属于个人信息：只在用户点击后请求（服务器记审计）。 */
export function useExposureAccounts(alertId: number, enabled: boolean) {
  return useQuery({
    queryKey: keys.exposureAccounts(alertId),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/alerts/{alert_id}/exposure/accounts", { params: { path: { alert_id: alertId } } })),
    enabled,
    staleTime: 0,
    gcTime: 0,
  });
}

export function usePushExposure(alertId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (_: void) =>
      unwrap(await api.POST("/api/v1/alerts/{alert_id}/exposure/push", { params: { path: { alert_id: alertId } } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.exposure(alertId) });
      void qc.invalidateQueries({ queryKey: keys.exposureAccounts(alertId) });
      void qc.invalidateQueries({ queryKey: keys.alert(alertId) });
    },
  });
}

export function useReports(kind: ReportKind, page = 1, pageSize = 20) {
  return useQuery({
    queryKey: [...keys.reports(kind), page, pageSize],
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/reports", {
        params: { query: { kind: kind || undefined, page, limit: pageSize } },
      })),
  });
}

export function useReport(id: number) {
  return useQuery({
    queryKey: keys.report(id),
    queryFn: async () => unwrap(await api.GET("/api/v1/reports/{report_id}", { params: { path: { report_id: id } } })),
    enabled: Number.isInteger(id) && id > 0,
  });
}

/** 参数相同的卡片共用一次请求（查询键包含天数、类别、条数）。 */
export function useDashboard(q: DashboardQuery) {
  return useQuery({
    queryKey: keys.dashboard(q),
    queryFn: async () =>
      unwrap(
        await api.GET("/api/v1/dashboard", {
          params: { query: { days: q.days, category: q.category ?? undefined, limit: q.limit ?? 10 } },
        }),
      ),
  });
}

export function useDashboardLayout() {
  return useQuery({
    queryKey: keys.dashboardLayout,
    queryFn: async () => unwrap(await api.GET("/api/v1/dashboard/layout")),
  });
}

export function useDefaultLayout(enabled: boolean) {
  return useQuery({
    queryKey: keys.dashboardDefault,
    enabled,
    queryFn: async () => unwrap(await api.GET("/api/v1/dashboard/layout/default")),
  });
}

function useLayoutMutation<V>(send: (v: V) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: send,
    // 等新布局取回来才算完成，调用方此时再退出编辑，页面不会闪回旧布局
    onSuccess: () =>
      Promise.all([
        qc.invalidateQueries({ queryKey: keys.dashboardLayout }),
        qc.invalidateQueries({ queryKey: keys.dashboardDefault }),
      ]),
  });
}

/** 保存后直接写入缓存，页面立即换成新布局，不闪回旧布局。 */
export function useSaveLayout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: LayoutSpec) => unwrap(await api.PUT("/api/v1/dashboard/layout", { body })),
    onSuccess: (data) => qc.setQueryData(keys.dashboardLayout, data),
  });
}

export function useResetLayout() {
  return useLayoutMutation(async (_: void) => unwrap(await api.DELETE("/api/v1/dashboard/layout")));
}

export function useSaveDefaultLayout() {
  return useLayoutMutation(async (body: LayoutSpec) => unwrap(await api.PUT("/api/v1/dashboard/layout/default", { body })));
}

export function useClearDefaultLayout() {
  return useLayoutMutation(async (_: void) => unwrap(await api.DELETE("/api/v1/dashboard/layout/default")));
}

/** 指派给我的未结告警：由服务器按紧急程度（严重程度高、同级别先建的在前）取前 limit 条。 */
export function useMyAlerts(limit: number) {
  return useQuery({
    queryKey: keys.myAlerts(limit),
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/alerts", { params: { query: { assigned_to_me: true, order: "urgency", limit } } })),
  });
}


export function useConnectors() {
  return useQuery({
    queryKey: keys.connectors,
    queryFn: async () => unwrap(await api.GET("/api/v1/connectors")),
    refetchInterval: 30_000,
  });
}

export function useConnectorConfig(id: string | null) {
  return useQuery({
    queryKey: ["connector-config", id],
    enabled: !!id,
    queryFn: async () => unwrap(await api.GET("/api/v1/connectors/{connector_id}/config", { params: { path: { connector_id: id! } } })),
  });
}

export function useSaveConnectorConfig(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Schemas["ConnectorConfigIn"]) =>
      unwrap(await api.PUT("/api/v1/connectors/{connector_id}/config", { params: { path: { connector_id: id } }, body })),
    onSuccess: () => invalidateConnector(qc, id),
  });
}

export function useConnectorHistory(id: string | null, enabled: boolean) {
  return useQuery({
    queryKey: ["connector-history", id],
    enabled: !!id && enabled,
    queryFn: async () => unwrap(await api.GET("/api/v1/connectors/{connector_id}/history", { params: { path: { connector_id: id! } } })),
  });
}

export function useRestoreConnector(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (version: number) =>
      unwrap(await api.POST("/api/v1/connectors/{connector_id}/restore", { params: { path: { connector_id: id } }, body: { version } })),
    onSuccess: () => invalidateConnector(qc, id),
  });
}

function invalidateConnector(qc: ReturnType<typeof useQueryClient>, id: string) {
  void qc.invalidateQueries({ queryKey: keys.connectors });
  void qc.invalidateQueries({ queryKey: ["connector-config", id] });
  void qc.invalidateQueries({ queryKey: ["connector-history", id] });
}

export function useSaveConnectorApproval(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Schemas["ConnectorApprovalIn"]) =>
      unwrap(await api.PUT("/api/v1/connectors/{connector_id}/approval", { params: { path: { connector_id: id } }, body })),
    onSuccess: () => invalidateConnector(qc, id),
  });
}

export function usePlatformCheck(url: string) {
  const value = url.trim();
  return useQuery({
    queryKey: ["submission-platform", value] as const,
    enabled: value.length > 0,
    queryFn: async () => unwrap(await api.GET("/api/v1/submissions/platform", { params: { query: { url: value } } })),
  });
}

export function useSubmitLead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Schemas["SubmissionIn"]) => unwrap(await api.POST("/api/v1/submissions", { body })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.alertsAll }),
  });
}

/** 请求体就是图片本身（不是表单），由服务器核验格式并去除元数据。 */
export async function uploadEvidence(alertId: number, file: File): Promise<Schemas["EvidenceOut"]> {
  const r = await globalThis.fetch(`/api/v1/alerts/${alertId}/evidence`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": file.type || "application/octet-stream", "X-Requested-With": "opti" },
    body: file,
  });
  const data: unknown = await r.json().catch(() => null);
  if (!r.ok) throw new ApiError(r.status, data);
  return data as Schemas["EvidenceOut"];
}

export function useUploadEvidence(alertId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => uploadEvidence(alertId, file),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.alert(alertId) }),
  });
}

export function useCampaigns(state: CampaignState, page: number, pageSize = 20) {
  return useQuery({
    queryKey: [...keys.campaigns(state, page), pageSize],
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/campaigns", { params: { query: { state, page, page_size: pageSize } } })),
  });
}

export function useCampaign(id: number) {
  return useQuery({
    queryKey: keys.campaign(id),
    queryFn: async () => unwrap(await api.GET("/api/v1/campaigns/{campaign_id}", { params: { path: { campaign_id: id } } })),
    enabled: Number.isInteger(id) && id > 0,
  });
}

function useCampaignMutation<B, R>(id: number, send: (body: B) => Promise<R>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: send,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.campaign(id) });
      void qc.invalidateQueries({ queryKey: keys.campaignsAll });
      void qc.invalidateQueries({ queryKey: keys.alertsAll });
    },
  });
}

export function useUpdateCampaign(id: number) {
  return useCampaignMutation(id, async (body: Schemas["CampaignUpdate"]) =>
    unwrap(await api.PATCH("/api/v1/campaigns/{campaign_id}", { params: { path: { campaign_id: id } }, body })),
  );
}

export function useDecideMember(id: number) {
  return useCampaignMutation(id, async (v: { findingId: number; decision: "accept" | "reject" | "remove" }) =>
    unwrap(
      await api.POST("/api/v1/campaigns/{campaign_id}/members/{finding_id}", {
        params: { path: { campaign_id: id, finding_id: v.findingId } },
        body: { decision: v.decision },
      }),
    ),
  );
}

export function useCampaignBulk(id: number) {
  return useCampaignMutation(id, async (body: Schemas["CampaignBulk"]) =>
    unwrap(await api.POST("/api/v1/campaigns/{campaign_id}/bulk", { params: { path: { campaign_id: id } }, body })),
  );
}


export function useLlmPresets() {
  return useQuery({
    queryKey: keys.llmPresets,
    queryFn: async () => unwrap(await api.GET("/api/v1/llm/presets")),
    staleTime: Infinity,
  });
}

export function useLlmStatus() {
  return useQuery({ queryKey: keys.llmStatus, queryFn: async () => unwrap(await api.GET("/api/v1/llm/status")) });
}

export function useLlmSettings() {
  return useQuery({ queryKey: keys.llmSettings, queryFn: async () => unwrap(await api.GET("/api/v1/llm/settings")) });
}

export function useLlmProviders() {
  return useQuery({ queryKey: keys.llmProviders, queryFn: async () => unwrap(await api.GET("/api/v1/llm/providers")) });
}

function useLlmMutation<A, R>(fn: (arg: A) => Promise<R>) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSuccess: () => qc.invalidateQueries({ queryKey: keys.llmAll }) });
}

export function useSaveLlmSettings() {
  return useLlmMutation(async (body: Schemas["LlmSettingsIn"]) => unwrap(await api.PUT("/api/v1/llm/settings", { body })));
}

export function useCreateLlmProvider() {
  return useLlmMutation(async (body: Schemas["LlmProviderIn"]) => unwrap(await api.POST("/api/v1/llm/providers", { body })));
}

export function useUpdateLlmProvider() {
  return useLlmMutation(async ({ id, body }: { id: number; body: Schemas["LlmProviderPatch"] }) =>
    unwrap(await api.PATCH("/api/v1/llm/providers/{provider_id}", { params: { path: { provider_id: id } }, body })),
  );
}

export function useDeleteLlmProvider() {
  return useLlmMutation(async (id: number) =>
    unwrap(await api.DELETE("/api/v1/llm/providers/{provider_id}", { params: { path: { provider_id: id } } })),
  );
}

export function useTestLlmProvider() {
  return useLlmMutation(async (id: number) =>
    unwrap(await api.POST("/api/v1/llm/providers/{provider_id}/test", { params: { path: { provider_id: id } } })),
  );
}

export function useLlmModels() {
  return useMutation({
    mutationFn: async (id: number) =>
      unwrap(await api.POST("/api/v1/llm/providers/{provider_id}/models", { params: { path: { provider_id: id } } })),
  });
}

export function useConfig(kind: ConfigKind, enabled = true) {
  return useQuery({
    queryKey: keys.config(kind),
    enabled,
    queryFn: async () => unwrap(await api.GET("/api/v1/config/{kind}", { params: { path: { kind } } })),
  });
}

export function useConfigStatus() {
  return useQuery({
    queryKey: keys.configStatus,
    queryFn: async () => unwrap(await api.GET("/api/v1/config/status")),
    refetchInterval: 5000,
  });
}

export function useConfigRevisions(kind: ConfigKind, enabled: boolean) {
  return useQuery({
    queryKey: keys.configRevisions(kind),
    enabled,
    queryFn: async () => unwrap(await api.GET("/api/v1/config/{kind}/revisions", { params: { path: { kind } } })),
  });
}

export function useConfigRevision(kind: ConfigKind, version: number | null) {
  return useQuery({
    queryKey: keys.configRevision(kind, version ?? 0),
    enabled: version !== null,
    queryFn: async () =>
      unwrap(await api.GET("/api/v1/config/{kind}/revisions/{version}", { params: { path: { kind, version: version ?? 0 } } })),
  });
}

export function useValidateConfig(kind: ConfigKind) {
  return useMutation({
    mutationFn: async (body: Schemas["ConfigValidateIn"]) =>
      unwrap(await api.POST("/api/v1/config/{kind}/validate", { params: { path: { kind } }, body })),
  });
}

function useConfigMutation<A, R>(fn: (arg: A) => Promise<R>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.configAll });
      qc.invalidateQueries({ queryKey: keys.configStatus });
    },
  });
}

export function useSaveConfig(kind: ConfigKind) {
  return useConfigMutation(async (draft: ConfigSaveDraft) =>
    unwrap(await api.PUT("/api/v1/config/{kind}", {
      params: { path: { kind } },
      body: { confirm_project_change: false, confirm_oidc_change: false, confirm_retention: false, ...draft },
    })),
  );
}

export function useRestoreConfig(kind: ConfigKind) {
  return useConfigMutation(async ({ version, ...body }: Schemas["ConfigRestoreIn"] & { version: number }) =>
    unwrap(await api.POST("/api/v1/config/{kind}/revisions/{version}/restore", { params: { path: { kind, version } }, body })),
  );
}

export type SecretState = Schemas["ConfigSecretOut"];
export type SecretsListing = Schemas["ConfigSecretsOut"];
export type AlertingTestResult = Schemas["AlertingTestOut"];

export function useAlertingSecrets(enabled: boolean) {
  return useConfigSecrets("alerting", enabled);
}

export function useConfigSecrets(kind: ConfigKind, enabled: boolean) {
  return useQuery({
    queryKey: ["config", kind, "secrets"] as const,
    enabled,
    queryFn: async () => unwrap(await api.GET("/api/v1/config/{kind}/secrets", { params: { path: { kind } } })),
  });
}

export function useTemplatePreview() {
  return useMutation({
    mutationFn: async (body: Schemas["TemplatePreviewIn"]) =>
      unwrap(await api.POST("/api/v1/config/takedown_templates/preview", { body })),
  });
}

export function useRematchStatus(kind: "vendors" | "software") {
  return useQuery({
    queryKey: ["config", kind, "rematch"] as const,
    queryFn: async () => unwrap(await api.GET("/api/v1/config/{kind}/rematch", { params: { path: { kind } } })),
    refetchInterval: (query) => query.state.data?.status === "queued" ? 5000 : false,
  });
}

export function useKevProducts(vendor: string | undefined) {
  return useQuery({
    queryKey: ["kev-products", vendor ?? ""] as const,
    enabled: !!vendor?.trim(),
    staleTime: 60_000,
    queryFn: async () => unwrap(await api.GET("/api/v1/config/software/kev-products", { params: { query: { vendor: vendor ?? "" } } })),
  });
}

export function useTestSharing() {
  return useMutation({
    mutationFn: async (body: Schemas["SharingTestIn"]) => unwrap(await api.POST("/api/v1/config/sharing/test", { body })),
  });
}

export function useTestTickets() {
  return useMutation({
    mutationFn: async () => unwrap(await api.POST("/api/v1/config/tickets/test")),
  });
}

export function useTestAlertingChannel() {
  return useMutation({
    mutationFn: async (body: Schemas["AlertingTestIn"]) => unwrap(await api.POST("/api/v1/config/alerting/test", { body })),
  });
}
