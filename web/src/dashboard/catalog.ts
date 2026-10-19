import type { TFunction } from "i18next";
import type { Schemas } from "../api/client";

export type Layout = Schemas["LayoutSpec"];
export type Widget = Schemas["LayoutWidget"];
export type ParamName = "days" | "category" | "limit" | "metric";

/** 卡片类型的元数据；渲染组件在 widgets/index.ts，两者按 type 对应。 */
export interface WidgetDef {
  type: string;
  titleKey: string;
  perm: string;
  w: number;
  h: number;
  minW: number;
  minH: number;
  params: ParamName[];
  /** 显示条数上限：排行类卡片受服务器返回条数限制（类别 20、来源 15、托管 10）。 */
  maxLimit: number;
}

export const GRID_COLS = 12;
/** 与服务器校验一致：一个布局最多 30 张卡片。 */
export const MAX_WIDGETS = 30;
export const MAX_H = 24;
export const ROW_HEIGHT = 48;
export const GRID_MARGIN = 16;
export const DAY_OPTIONS = [7, 30, 90] as const;
export const DEFAULT_LIMIT = 10;
export const METRICS = ["open_critical", "open_high", "open_medium", "new_alerts", "new_findings", "mttr"] as const;
export type Metric = (typeof METRICS)[number];
/** 告警类别（与后端 opti.core.scoring.Category 一致），供类别过滤下拉框使用。 */
export const CATEGORIES = [
  "phishing_site", "typosquat_domain", "unapproved_certificate", "reported_phishing", "clone_site", "email_spoofing",
  "credential_exposure", "ransomware_mention", "secret_leak", "data_leak", "brand_mention", "negative_press",
  "fraud_scam", "vulnerability", "threat_intel", "impersonation_account",
] as const;

const def = (type: string, perm: string, w: number, h: number, params: ParamName[], minW = 3, minH = 3, maxLimit = 50): WidgetDef => ({
  type, titleKey: `dashboard.widget.${type}`, perm, w, h, minW, minH, params, maxLimit,
});

export const CATALOG: WidgetDef[] = [
  def("stat", "alerts:read", 2, 2, ["metric", "days"], 2, 2),
  def("trend", "alerts:read", 8, 5, ["days", "category"], 4),
  def("mttd", "alerts:read", 4, 5, ["days"]),
  def("by_category", "alerts:read", 6, 5, ["days", "limit"], 3, 3, 20),
  def("by_source", "alerts:read", 6, 5, ["days", "limit"], 3, 3, 15),
  def("overdue", "alerts:read", 12, 5, ["category", "limit"], 4),
  def("top", "alerts:read", 12, 5, ["category", "limit"], 4),
  def("countries", "alerts:read", 6, 5, ["days", "limit"], 3, 3, 10),
  def("networks", "alerts:read", 6, 5, ["days", "limit"], 3, 3, 10),
  def("my_todo", "alerts:triage", 6, 5, ["limit"], 4),
  def("takedowns", "takedown:read", 6, 5, [], 4),
  def("campaigns", "evidence:read", 6, 5, ["limit"], 4),
  def("connector_health", "connectors:read", 6, 5, [], 4),
];

export const CATALOG_BY_TYPE: Record<string, WidgetDef> = Object.fromEntries(CATALOG.map((d) => [d.type, d]));

/** 新增卡片时的参数初值：全部"跟随全局"，指标卡默认未处理严重告警。 */
export function defaultParams(d: WidgetDef): Widget["params"] {
  return Object.fromEntries(d.params.map((p) => [p, p === "metric" ? "open_critical" : null]));
}

export function widgetTitle(t: TFunction, w: Widget): string {
  if (w.type === "stat") return t(`dashboard.metric.${String(w.params.metric)}`);
  const d = CATALOG_BY_TYPE[w.type];
  return d ? t(d.titleKey) : w.type;
}

const stat = (id: string, x: number, metric: Metric): Widget => ({ id, type: "stat", x, y: 0, w: 2, h: 2, params: { metric, days: null } });
const block = (type: string, x: number, y: number, w: number, params: Widget["params"]): Widget => ({ id: type, type, x, y, w, h: 5, params });

/** 没有个人布局、也没有机构默认时使用；排列与改造前的总览页一致。 */
export const BUILTIN_LAYOUT: Layout = {
  version: 1,
  days: 30,
  widgets: [
    stat("open_critical", 0, "open_critical"),
    stat("open_high", 2, "open_high"),
    stat("open_medium", 4, "open_medium"),
    stat("new_alerts", 6, "new_alerts"),
    stat("new_findings", 8, "new_findings"),
    stat("mttr", 10, "mttr"),
    block("trend", 0, 2, 8, { days: null, category: null }),
    block("mttd", 8, 2, 4, { days: null }),
    block("by_category", 0, 7, 6, { days: null, limit: null }),
    block("by_source", 6, 7, 6, { days: null, limit: null }),
    block("overdue", 0, 12, 12, { category: null, limit: null }),
    block("top", 0, 17, 12, { category: null, limit: null }),
    block("countries", 0, 22, 6, { days: null, limit: null }),
    block("networks", 6, 22, 6, { days: null, limit: null }),
  ],
};
