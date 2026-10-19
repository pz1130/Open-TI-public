import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import CertificatesPage from "./CertificatesPage";
import { ME_ADMIN, ME_ANALYST, ME_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

const MONITOR = { id: 1, root_domain: "example.com", enabled: true, warn_days: 30, known_domains: [], created_at: "2026-10-14T00:00:00Z", last_checked_at: "2026-10-14T01:00:00Z", next_check_at: "2026-10-15T01:00:00Z", scanning: false, error: null, truncated: false, host_count: 2 };
const HOST = { id: 2, domain: "www.example.com", state: "expiring", checked_at: "2026-10-14T01:00:00Z", certificate_checked_at: "2026-10-14T01:00:00Z", not_after: "2026-10-20T01:00:00Z", days_remaining: 6, issuer: "Test CA", error: null };

test("查看证书状态和失败后保留的证书，不把失败当作有效", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/certificate-monitors", () => HttpResponse.json({ items: [{ ...MONITOR, error: "tls_failed:1", truncated: true }], next_cursor: null })),
    http.get("*/api/v1/certificate-monitors/1/hosts", () => HttpResponse.json({ items: [HOST, { ...HOST, id: 3, domain: "mail.example.com", state: "error", days_remaining: null, error: "TimeoutError" }], next_cursor: null })),
  );
  const user = userEvent.setup();
  renderApp(<CertificatesPage />);
  await user.click(await screen.findByRole("button", { name: "查看证书" }));
  expect(await screen.findByText("www.example.com")).toBeInTheDocument();
  expect(screen.getByText("即将到期")).toBeInTheDocument();
  expect(screen.getByText("检查失败")).toBeInTheDocument();
  expect(screen.getByText("6 天")).toBeInTheDocument();
  expect(screen.getByText(/当前结果不完整/)).toBeInTheDocument();
});

test("添加根域名、补充子域名、修改提前提醒和立即检查", async () => {
  let saved: unknown;
  let checked = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/certificate-monitors", () => HttpResponse.json({ items: [MONITOR], next_cursor: null })),
    http.post("*/api/v1/certificate-monitors", async ({ request }) => { saved = await request.json(); return HttpResponse.json(MONITOR, { status: 201 }); }),
    http.post("*/api/v1/certificate-monitors/1/check", () => { checked++; return new HttpResponse(null, { status: 202 }); }),
  );
  const user = userEvent.setup();
  renderApp(<CertificatesPage />);
  await user.click(await screen.findByRole("button", { name: "添加根域名" }));
  expect(await screen.findByText(/必须是规则中的官方域名或其子域名/)).toBeInTheDocument();
  await user.type(await screen.findByLabelText("根域名"), "another.example");
  await user.type(screen.getByLabelText("补充已知子域名"), "www.another.example\nmail.another.example");
  const days = screen.getByLabelText("提前告警天数");
  await user.clear(days);
  await user.type(days, "14");
  await user.click(screen.getByRole("button", { name: "确定" }));
  await waitFor(() => expect(saved).toEqual({ root_domain: "another.example", warn_days: 14, enabled: true, known_domains: ["www.another.example", "mail.another.example"] }));
  await user.click(screen.getByRole("button", { name: "立即检查" }));
  await waitFor(() => expect(checked).toBe(1));
  expect(await screen.findByText("已安排检查，结果会自动刷新")).toBeInTheDocument();
});

test("只读用户不能添加、修改或检查", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/certificate-monitors", () => HttpResponse.json({ items: [MONITOR], next_cursor: null })),
  );
  renderApp(<CertificatesPage />);
  expect(await screen.findByText("example.com")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "添加根域名" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "立即检查" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "编辑监控" })).not.toBeInTheDocument();
});

test("连续失败满 30 天的主机显示已停查，并提示如何恢复检查", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/certificate-monitors", () => HttpResponse.json({ items: [MONITOR], next_cursor: null })),
    http.get("*/api/v1/certificate-monitors/1/hosts", () => HttpResponse.json({ items: [{ ...HOST, id: 4, domain: "old.example.com", state: "retired", days_remaining: null, error: "ConnectionRefusedError" }], next_cursor: null })),
  );
  const user = userEvent.setup();
  renderApp(<CertificatesPage />);
  await user.click(await screen.findByRole("button", { name: "查看证书" }));
  const tag = await screen.findByText("已停查");
  await user.hover(tag);
  expect(await screen.findByText(/连续 30 天无法读取证书，已停止检查/)).toBeInTheDocument();
});


test("管理员有监控写权限，详情翻页和搜索使用独立页码", async () => {
  const seen: URLSearchParams[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ADMIN)),
    http.get("*/api/v1/certificate-monitors", () => HttpResponse.json({ items: [MONITOR], total: 1, next_cursor: null })),
    http.get("*/api/v1/certificate-monitors/1/hosts", ({ request }) => {
      const params = new URL(request.url).searchParams;
      seen.push(params);
      return HttpResponse.json({ items: [{ ...HOST, domain: params.get("page") === "2" ? "api.example.com" : HOST.domain }], total: 21, next_cursor: null });
    }),
  );
  const user = userEvent.setup();
  renderApp(<CertificatesPage />);
  expect(await screen.findByRole("button", { name: "添加根域名" })).toBeInTheDocument();
  await user.click(await screen.findByRole("button", { name: "查看证书" }));
  await screen.findByText(HOST.domain);
  await user.click(screen.getByTitle("2"));
  expect(await screen.findByText("api.example.com")).toBeInTheDocument();
  expect(screen.queryByText(HOST.domain)).toBeNull();
  await user.type(screen.getByPlaceholderText("搜索子域名"), "api{Enter}");
  await waitFor(() => expect(seen.at(-1)?.get("q")).toBe("api"));
  expect(seen.at(-1)?.get("page")).toBe("1");
});


test("管理员确认发现的域名并可配置独立提前天数", async () => {
  let approved = false;
  let days: number | null = null;
  const bodies: unknown[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ADMIN)),
    http.get("*/api/v1/certificate-monitors", () => HttpResponse.json({ items: [MONITOR], total: 1, next_cursor: null })),
    http.get("*/api/v1/certificate-monitors/1/hosts", () => HttpResponse.json({ items: [{ ...HOST, approved, warn_days: days, effective_warn_days: days ?? 30 }], total: 1, next_cursor: null })),
    http.put("*/api/v1/certificate-monitors/1/hosts/2", async ({ request }) => {
      const body = await request.json() as { approved: boolean; warn_days: number | null };
      bodies.push(body);
      approved = body.approved;
      days = body.warn_days;
      return new HttpResponse(null, { status: 204 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<CertificatesPage />);
  await user.click(await screen.findByRole("button", { name: "查看证书" }));
  expect(await screen.findByText("待管理员确认")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "确认告警" }));
  await waitFor(() => expect(bodies).toEqual([{ approved: true, warn_days: null }]));
  expect(await screen.findByText("已确认告警")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "配置证书告警" }));
  await user.type(await screen.findByLabelText("提前告警天数"), "14");
  await user.click(screen.getByRole("button", { name: "确定" }));
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[1]).toEqual({ approved: true, warn_days: 14 });
});


test("分析员可查看待确认结果但不能确认", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/certificate-monitors", () => HttpResponse.json({ items: [MONITOR], total: 1, next_cursor: null })),
    http.get("*/api/v1/certificate-monitors/1/hosts", () => HttpResponse.json({ items: [{ ...HOST, approved: false, warn_days: null }], total: 1, next_cursor: null })),
  );
  const user = userEvent.setup();
  renderApp(<CertificatesPage />);
  await user.click(await screen.findByRole("button", { name: "查看证书" }));
  expect(await screen.findByText("待管理员确认")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "确认告警" })).toBeNull();
  expect(screen.queryByRole("button", { name: "配置证书告警" })).toBeNull();
});
