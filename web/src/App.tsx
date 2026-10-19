import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider, Result, Spin, theme } from "antd";
import enUS from "antd/locale/en_US";
import zhCN from "antd/locale/zh_CN";
import dayjs from "dayjs";
import "dayjs/locale/zh-cn";
import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { ApiError } from "./api/client";
import { keys, useMe } from "./api/hooks";
import { can } from "./auth/perms";
import QueryError from "./components/QueryError";
import AppLayout from "./components/AppLayout";
import { PageSuspense } from "./components/PageLoader";
import LoginPage from "./pages/LoginPage";
import PasswordPage from "./pages/PasswordPage";
import { PAGES } from "./pages/registry";

import { ThemeProvider, useTheme } from "./theme";

export function makeQueryClient(): QueryClient {
  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.status === 401) client.setQueryData(keys.me, null); // 会话过期：回到登录页
  };
  const client: QueryClient = new QueryClient({
    queryCache: new QueryCache({ onError }),
    mutationCache: new MutationCache({ onError }),
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
        retry: (count, e) => !(e instanceof ApiError && e.status < 500) && count < 2,
      },
    },
  });
  return client;
}

/** 界面文字用系统字体栈（含中文字体），数字与域名用打包的 JetBrains Mono。 */
const FONT_UI =
  "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', 'Noto Sans CJK SC', 'Noto Sans SC', Roboto, 'Helvetica Neue', Arial, sans-serif";
const FONT_MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

function ThemedConfigProvider({ english, children }: { english: boolean; children: ReactNode }) {
  const { theme: themeMode } = useTheme();
  const isDark = themeMode === "dark";

  return (
    <ConfigProvider
      locale={english ? enUS : zhCN}
      button={{ autoInsertSpace: false }}
      theme={{
        algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          ...(isDark
            ? {
                colorPrimary: "#8b93ff",
                colorInfo: "#8b93ff",
                colorSuccess: "#34b98a",
                colorWarning: "#eab541",
                colorError: "#f43f5e",
                colorLink: "#a5abff",
                colorBgBase: "#08090d",
                colorBgContainer: "#11131a",
                colorBgElevated: "#171a23",
                colorBgLayout: "#08090d",
                colorBorder: "rgba(160, 170, 200, 0.16)",
                colorBorderSecondary: "rgba(160, 170, 200, 0.09)",
                colorText: "#e7e9f0",
                colorTextSecondary: "#9aa1b4",
                colorTextTertiary: "#6c7387",
                colorTextHeading: "#f3f4f8",
              }
            : {
                colorPrimary: "#4f55d6",
                colorInfo: "#4f55d6",
                colorSuccess: "#16976a",
                colorWarning: "#c48a12",
                colorError: "#e11d48",
                colorLink: "#4047c4",
                colorBgBase: "#f4f5f9",
                colorBgContainer: "#ffffff",
                colorBgElevated: "#ffffff",
                colorBgLayout: "#f4f5f9",
                colorBorder: "rgba(22, 27, 45, 0.13)",
                colorBorderSecondary: "rgba(22, 27, 45, 0.07)",
                colorText: "#161a26",
                colorTextSecondary: "#5a6175",
                colorTextTertiary: "#8a90a2",
                colorTextHeading: "#10131d",
              }),
          borderRadius: 8,
          borderRadiusSM: 6,
          borderRadiusLG: 12,
          fontSize: 14,
          fontFamily: FONT_UI,
          fontFamilyCode: FONT_MONO,
          motionDurationMid: "0.22s",
          motionEaseInOut: "cubic-bezier(0.22, 1, 0.36, 1)",
        },
        components: {
          Card: {
            colorBgContainer: "transparent",
            headerBg: "transparent",
            headerFontSize: 14,
          },
          Table: {
            headerBg: "transparent",
            headerColor: isDark ? "#9aa1b4" : "#5a6175",
            rowHoverBg: isDark ? "rgba(139, 147, 255, 0.06)" : "rgba(79, 85, 214, 0.04)",
            borderColor: isDark ? "rgba(160, 170, 200, 0.08)" : "rgba(22, 27, 45, 0.07)",
            headerSplitColor: "transparent",
          },
          Button: {
            fontWeight: 500,
            primaryShadow: "none",
          },
          Segmented: {
            itemSelectedBg: isDark ? "#262a3a" : "#ffffff",
            trackBg: isDark ? "rgba(160, 170, 200, 0.08)" : "rgba(22, 27, 45, 0.06)",
          },
          Tooltip: {
            colorBgSpotlight: isDark ? "#1d2030" : "#161a26",
          },
        },
      }}
    >
      <AntApp>{children}</AntApp>
    </ConfigProvider>
  );
}

export function Providers({ client, children }: { client: QueryClient; children: ReactNode }) {
  const { i18n } = useTranslation();
  const english = i18n.language === "en-US";
  useEffect(() => {
    dayjs.locale(english ? "en" : "zh-cn");
    document.documentElement.lang = i18n.language;
  }, [english, i18n.language]);

  return (
    <QueryClientProvider client={client}>
      <ThemeProvider>
        <ThemedConfigProvider english={english}>{children}</ThemedConfigProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export function AppRoutes() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spin fullscreen />;
  if (me.isError) return <QueryError error={me.error} />;
  if (!me.data) return <LoginPage />;
  if (me.data.must_change_password) return <PasswordPage forced />;
  const allowed = PAGES.filter((p) => can(me.data, p.perm));
  const home = allowed.find((p) => p.nav);
  return (
    <Routes>
      <Route element={<AppLayout me={me.data} />}>
        {me.data.auth_source === "local" && <Route path="account/password" element={<PasswordPage />} />}
        <Route index element={home ? <Navigate to={`/${home.path}`} replace /> : <Result status="403" title={t("common.forbidden")} />} />
        {allowed.map((p) => (
          <Route key={p.path} path={p.path} element={<PageSuspense>{p.element}</PageSuspense>} />
        ))}
        <Route path="*" element={<Result status="404" title={t("common.notFound")} />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  const [client] = useState(makeQueryClient);
  return (
    <Providers client={client}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </Providers>
  );
}
