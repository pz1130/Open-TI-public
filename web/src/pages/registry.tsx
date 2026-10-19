import { FlagOutlined, AlertOutlined, ClusterOutlined, EyeOutlined, ExperimentOutlined, StopOutlined, AuditOutlined, FileTextOutlined } from "@ant-design/icons";
import { ApiOutlined, DashboardOutlined, RobotOutlined, SafetyCertificateOutlined, SearchOutlined, SettingOutlined, UserSwitchOutlined } from "@ant-design/icons";
import type { ReactNode } from "react";
import { lazyPage } from "../components/PageLoader";

/** 页面按需加载：首屏只下载外壳与当前页，其余页面在首次进入时再取。 */
const TakedownsPage = lazyPage(() => import("./TakedownsPage"));
const AlertQueuePage = lazyPage(() => import("./AlertQueuePage"));
const AlertDetailPage = lazyPage(() => import("./AlertDetailPage"));
const CampaignsPage = lazyPage(() => import("./CampaignsPage"));
const CampaignDetailPage = lazyPage(() => import("./CampaignDetailPage"));
const WatchlistPage = lazyPage(() => import("./WatchlistPage"));
const CertificatesPage = lazyPage(() => import("./CertificatesPage"));
const SocialAccountsPage = lazyPage(() => import("./SocialAccountsPage"));
const SandboxPage = lazyPage(() => import("./SandboxPage"));
const SuppressionsPage = lazyPage(() => import("./SuppressionsPage"));
const AuditLogPage = lazyPage(() => import("./AuditLogPage"));
const SearchPage = lazyPage(() => import("./SearchPage"));
const ReportsPage = lazyPage(() => import("./ReportsPage"));
const DashboardPage = lazyPage(() => import("./DashboardPage"));
const ConnectorsPage = lazyPage(() => import("./ConnectorsPage"));
const LlmPage = lazyPage(() => import("./LlmPage"));
const SettingsPage = lazyPage(() => import("./SettingsPage"));
const ReportDetailPage = lazyPage(() => import("./ReportDetailPage"));

/** 页面注册表：路由与左侧菜单都从这里生成；Task 9、10 在此追加页面。 */
export interface PageDef {
  path: string; // 路由路径（不带前导斜杠），如 "alerts"、"alerts/:id"
  perm: string | readonly string[]; // 需要的权限点；数组表示满足任一即可
  labelKey?: string; // 菜单文案键；没有则不出现在菜单中
  icon?: ReactNode;
  element: ReactNode;
  nav: boolean;
}

export const PAGES: PageDef[] = [
  { path: "dashboard", perm: ["alerts:read", "dashboard:default"], labelKey: "nav.dashboard", icon: <DashboardOutlined />, element: <DashboardPage />, nav: true },
  { path: "alerts", perm: "alerts:read", labelKey: "nav.alerts", icon: <AlertOutlined />, element: <AlertQueuePage />, nav: true },
  { path: "search", perm: "documents:read", labelKey: "nav.search", icon: <SearchOutlined />, element: <SearchPage />, nav: true },
  { path: "reports", perm: "reports:read", labelKey: "nav.reports", icon: <FileTextOutlined />, element: <ReportsPage />, nav: true },
  { path: "reports/:id", perm: "reports:read", element: <ReportDetailPage />, nav: false },
  { path: "alerts/:id", perm: "alerts:read", element: <AlertDetailPage />, nav: false },
  { path: "campaigns", perm: "evidence:read", labelKey: "nav.campaigns", icon: <ClusterOutlined />, element: <CampaignsPage />, nav: true },
  { path: "campaigns/:id", perm: "evidence:read", element: <CampaignDetailPage />, nav: false },
  { path: "watchlist", perm: "watchlist:read", labelKey: "nav.watchlist", icon: <EyeOutlined />, element: <WatchlistPage />, nav: true },
  { path: "certificates", perm: "certificates:read", labelKey: "nav.certificates", icon: <SafetyCertificateOutlined />, element: <CertificatesPage />, nav: true },
  { path: "social-accounts", perm: "watchlist:read", labelKey: "nav.socialAccounts", icon: <UserSwitchOutlined />, element: <SocialAccountsPage />, nav: true },
  { path: "sandbox", perm: "rules:test", labelKey: "nav.sandbox", icon: <ExperimentOutlined />, element: <SandboxPage />, nav: true },
  { path: "takedowns", perm: "takedown:read", labelKey: "nav.takedowns", icon: <FlagOutlined />, element: <TakedownsPage />, nav: true },
  { path: "suppressions", perm: "suppressions:read", labelKey: "nav.suppressions", icon: <StopOutlined />, element: <SuppressionsPage />, nav: true },
  { path: "audit", perm: "audit:read", labelKey: "nav.audit", icon: <AuditOutlined />, element: <AuditLogPage />, nav: true },
  { path: "connectors", perm: "connectors:read", labelKey: "nav.connectors", icon: <ApiOutlined />, element: <ConnectorsPage />, nav: true },
  { path: "llm", perm: "llm:read", labelKey: "nav.llm", icon: <RobotOutlined />, element: <LlmPage />, nav: true },
  { path: "settings", perm: ["config:read", "users:write", "access:write"], labelKey: "nav.settings", icon: <SettingOutlined />, element: <SettingsPage />, nav: true },
  { path: "settings/:kind", perm: ["config:read", "users:write", "access:write"], element: <SettingsPage />, nav: false },
];
