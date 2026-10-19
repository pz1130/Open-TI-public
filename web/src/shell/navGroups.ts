import type { PageDef } from "../pages/registry";

/** 侧栏分组：按工作流把页面分成「监测 → 研判处置 → 情报 → 平台」四段；没列出的页面归入平台管理。 */
export const NAV_GROUPS = ["monitor", "respond", "intel", "system"] as const;
export type NavGroup = (typeof NAV_GROUPS)[number];

const GROUP_OF: Record<string, NavGroup> = {
  dashboard: "monitor",
  alerts: "monitor",
  search: "monitor",
  watchlist: "monitor",
  certificates: "monitor",
  "social-accounts": "monitor",
  campaigns: "respond",
  takedowns: "respond",
  suppressions: "respond",
  reports: "intel",
  sandbox: "intel",
  llm: "intel",
  connectors: "system",
  audit: "system",
  settings: "system",
};

export const groupOf = (p: PageDef): NavGroup => GROUP_OF[p.path] ?? "system";

export function groupPages(pages: PageDef[]): { group: NavGroup; pages: PageDef[] }[] {
  return NAV_GROUPS.map((group) => ({ group, pages: pages.filter((p) => groupOf(p) === group) })).filter((g) => g.pages.length > 0);
}
