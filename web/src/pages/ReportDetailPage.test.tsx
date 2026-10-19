import { screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { Route, Routes } from "react-router";
import ReportDetailPage from "./ReportDetailPage";
import { ME_VIEWER, MONTHLY_REPORT, REPORT_DETAIL } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("显示概况、告警、漏洞与新闻；只有平台与新闻原文是链接", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/reports/3", () => HttpResponse.json(REPORT_DETAIL)),
  );
  renderApp(
    <Routes>
      <Route path="reports/:id" element={<ReportDetailPage />} />
    </Routes>,
    { route: "/reports/3" },
  );
  expect(await screen.findByText("威胁情报日报 2026-10-03")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "下载 HTML" })).toHaveAttribute("href", "/api/v1/reports/3/html");
  expect(screen.getByText("sbr-portal.top").closest("a")).toBeNull();
  const alertLinks = screen.getAllByRole("link", { name: "查看告警" });
  expect(alertLinks.map((a) => a.getAttribute("href"))).toEqual(["/alerts/7", "/alerts/8"]);
  const news = screen.getByRole("link", { name: "Bank approves loan" });
  expect(news).toHaveAttribute("href", "https://news.example/a");
  expect(news).toHaveAttribute("rel", "noopener noreferrer");
  expect(screen.getByText("CVE-2026-12345")).toBeInTheDocument();
  expect(screen.getByText("批准贷款")).toBeInTheDocument();
});

test("月报显示环比、近 6 个月趋势与重点事件的处置状态", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/reports/5", () => HttpResponse.json(MONTHLY_REPORT)),
  );
  renderApp(
    <Routes>
      <Route path="reports/:id" element={<ReportDetailPage />} />
    </Routes>,
    { route: "/reports/5" },
  );
  expect(await screen.findByText("威胁情报月报 2026-09")).toBeInTheDocument();
  expect(screen.getByText("4（上月 1，+3）")).toBeInTheDocument();
  expect(screen.getByText("8（上月 9，-1）")).toBeInTheDocument();
  expect(screen.queryByText("低级发现")).toBeNull();
  expect(screen.getByRole("img", { name: "近 6 个月告警趋势" })).toBeInTheDocument();
  expect(screen.getByRole("cell", { name: "2026-09" })).toBeInTheDocument();
  expect(screen.getByText("已关闭（真实威胁）· 下架：已提交")).toBeInTheDocument();
  expect(screen.getByText("负面舆情与冒名诈骗提及（共 12 条）")).toBeInTheDocument();
  expect(screen.getByText("已被利用漏洞（软件清单命中，共 0 条）")).toBeInTheDocument();
  expect(screen.getAllByRole("link", { name: "查看告警" }).map((a) => a.getAttribute("href"))).toEqual(["/alerts/7", "/alerts/8"]);
});
