import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import WatchedDomains from "./WatchedDomains";
import { ME_ANALYST, ME_VIEWER } from "../test/fixtures";
import { fmtTime } from "../components/format";
import { renderApp } from "../test/render";
import { server } from "../test/server";

const ENTRY = {
  id: 4, domain: "sbr-loans.com", state: "parked", reason: "certstream: score=48",
  created_at: "2026-10-01T00:00:00Z", last_checked_at: "2026-10-02T00:00:00Z",
  next_check_at: "2026-10-02T04:00:00Z", expires_at: null,
};

const PAGE_EVIDENCE = { id: 11, kind: "screenshot", content_type: "image/png", sha256: "a".repeat(64), size: 200, captured_at: "2026-10-02T00:00:00Z", node_id: "hk1", method: "sandbox-test", source_url: "https://sedo.com/domain/sbr-loans.com" };
const INSPECTION = { observed_at: "2026-10-02T00:00:00Z", verdict: "parking", source: "browser", title: "Domain marketplace", text_excerpt: "Buy this domain: sbr-loans.com", final_url: "https://sedo.com/domain/sbr-loans.com", redirects: ["https://sbr-loans.com/"], status: 200, brand_terms: [], has_password_field: false, capture_status: "done", evidence: [PAGE_EVIDENCE], error: null };

test("出售页覆盖已上线标签，并能查看正文、跳转地址、当前和历史截图", async () => {
  const older = { observed_at: "2026-10-01T00:00:00Z", state: "live", changes: [], fingerprint: {}, inspection: { ...INSPECTION, observed_at: "2026-10-01T00:00:00Z", verdict: "website", title: "Earlier foundation page", text_excerpt: "A previously active website", evidence: [{ ...PAGE_EVIDENCE, id: 12 }] } };
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/watchlist", () => HttpResponse.json({ items: [{ ...ENTRY, state: "live", inspection: INSPECTION }], next_cursor: null })),
    http.get("*/api/v1/watchlist/4/observations", () => HttpResponse.json([{ observed_at: INSPECTION.observed_at, state: "parked", changes: [], fingerprint: {}, inspection: INSPECTION }, older])),
  );
  const user = userEvent.setup();
  renderApp(<WatchedDomains />);
  expect(await screen.findByText("疑似停放 / 域名出售")).toBeInTheDocument();
  expect(screen.queryByText("已上线")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "页面内容与截图" }));
  expect(await screen.findByText("Buy this domain: sbr-loans.com")).toBeInTheDocument();
  expect(screen.getAllByText(INSPECTION.final_url).length).toBeGreaterThan(0);
  expect(screen.getAllByAltText("网页截图").some((image) => image.getAttribute("src") === "/api/v1/evidence/11/content")).toBe(true);
  await user.click(screen.getByRole("combobox", { name: "选择复查记录" }));
  await user.click(await screen.findByTitle(`${fmtTime(older.observed_at)} · 网页可访问`));
  expect(await screen.findByText("A previously active website")).toBeInTheDocument();
  expect(screen.getAllByAltText("网页截图").some((image) => image.getAttribute("src") === "/api/v1/evidence/12/content")).toBe(true);
});

test("本次失败会明确显示，并让用户从历史记录查看成功截图", async () => {
  const failed = { ...INSPECTION, source: "probe", verdict: "unavailable", title: "", text_excerpt: "", error: "TimeoutError", capture_status: "failed", evidence: [] };
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/watchlist", () => HttpResponse.json({ items: [{ ...ENTRY, state: "live", inspection: failed }], next_cursor: null })),
    http.get("*/api/v1/watchlist/4/observations", () => HttpResponse.json([{ observed_at: failed.observed_at, state: "live", changes: [], fingerprint: {}, inspection: failed }, { observed_at: "2026-10-01T00:00:00Z", state: "parked", changes: [], fingerprint: {}, inspection: INSPECTION }])),
  );
  const user = userEvent.setup();
  renderApp(<WatchedDomains />);
  expect(await screen.findByText("本次无法访问")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "页面内容与截图" }));
  expect(await screen.findByText(/本次截图失败/)).toBeInTheDocument();
  expect(screen.getByRole("combobox", { name: "选择复查记录" })).toBeInTheDocument();
});

test("没有证据权限的用户不会加载截图或获得快照下载链接", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/watchlist", () => HttpResponse.json({ items: [{ ...ENTRY, inspection: INSPECTION }], next_cursor: null })),
    http.get("*/api/v1/watchlist/4/observations", () => HttpResponse.json([{ observed_at: INSPECTION.observed_at, state: "parked", changes: [], fingerprint: {}, inspection: INSPECTION }])),
  );
  const user = userEvent.setup();
  renderApp(<WatchedDomains />);
  await user.click(await screen.findByRole("button", { name: "页面内容与截图" }));
  expect(await screen.findByText("Buy this domain: sbr-loans.com")).toBeInTheDocument();
  expect(screen.queryByAltText("网页截图")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "下载文本快照" })).not.toBeInTheDocument();
});

test("列表、加入、移出与时间线", async () => {
  const calls: string[] = [];
  let added: unknown = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/watchlist", () => HttpResponse.json({ items: [ENTRY], next_cursor: null })),
    http.post("*/api/v1/watchlist", async ({ request }) => {
      added = await request.json();
      return HttpResponse.json({ ...ENTRY, id: 5, domain: "sbr-grant.top", state: "unknown" }, { status: 201 });
    }),
    http.delete("*/api/v1/watchlist/4", ({ request }) => {
      calls.push(new URL(request.url).searchParams.get("reason") ?? "");
      return new HttpResponse(null, { status: 204 });
    }),
    http.get("*/api/v1/watchlist/4/observations", () =>
      HttpResponse.json([{ observed_at: "2026-10-02T00:00:00Z", state: "parked", changes: ["state:unknown->parked"], fingerprint: {} }]),
    ),
  );
  const user = userEvent.setup();
  renderApp(<WatchedDomains />);
  expect(await screen.findByText("sbr-loans.com")).toBeInTheDocument();
  expect(screen.getByText("停放")).toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: "状态时间线" }));
  expect(await screen.findByText(/state:unknown->parked/)).toBeInTheDocument();

  await user.click(await screen.findByRole("button", { name: "加入监视" }));
  await user.type(await screen.findByLabelText("域名"), "sbr-grant.top");
  await user.type(screen.getByLabelText("原因"), "举报邮件");
  await user.click(screen.getByRole("button", { name: "提交" }));
  await waitFor(() => expect(added).toEqual({ domain: "sbr-grant.top", reason: "举报邮件" }));

  await user.click(screen.getByRole("button", { name: "移出" }));
  await user.type(await screen.findByLabelText("移出原因"), "已注销");
  await user.click(screen.getAllByRole("button", { name: "提交" }).at(-1) as HTMLElement);
  await waitFor(() => expect(calls).toEqual(["已注销"]));
});

test("可以编辑监视域名和原因，并说明根域名监视范围", async () => {
  let updated: unknown = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/watchlist", () => HttpResponse.json({ items: [ENTRY], next_cursor: null })),
    http.put("*/api/v1/watchlist/4", async ({ request }) => {
      updated = await request.json();
      return HttpResponse.json({ ...ENTRY, id: 5, domain: "new.example", reason: "corrected" });
    }),
  );
  const user = userEvent.setup();
  renderApp(<WatchedDomains />);
  await user.click(await screen.findByRole("button", { name: "编辑" }));
  expect(await screen.findByText(/加入根域名不会自动扫描子域名/)).toBeInTheDocument();
  const domain = screen.getByLabelText("域名");
  const reason = screen.getByLabelText("原因");
  await user.clear(domain);
  await user.type(domain, "new.example");
  await user.clear(reason);
  await user.type(reason, "corrected");
  await user.click(screen.getByRole("button", { name: "保存修改" }));
  await waitFor(() => expect(updated).toEqual({ domain: "new.example", reason: "corrected" }));
});

test("立即检查只提交当前域名，并在完成后刷新状态", async () => {
  let queued = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/watchlist", () => HttpResponse.json({
      items: [queued
        ? { ...ENTRY, expires_at: "2030-01-01T00:00:00Z", state: "live", last_checked_at: "2026-10-02T01:00:00Z" }
        : { ...ENTRY, expires_at: "2030-01-01T00:00:00Z" }],
      next_cursor: null,
    })),
    http.post("*/api/v1/watchlist/4/check", () => {
      queued += 1;
      return HttpResponse.json({ status: "queued", watch_id: 4, request_id: "test-request" }, { status: 202 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<WatchedDomains />);
  await user.click(await screen.findByRole("button", { name: "立即检查" }));
  await waitFor(() => expect(queued).toBe(1));
  expect(await screen.findByText("已上线")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "立即检查" })).toBeInTheDocument();
});

test("提交期间不提示成功且阻止重复点击，收到回执后才显示已提交", async () => {
  let queued = 0;
  let acknowledge!: () => void;
  const gate = new Promise<void>((resolve) => { acknowledge = resolve; });
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/watchlist", () => HttpResponse.json({ items: [ENTRY], next_cursor: null })),
    http.post("*/api/v1/watchlist/4/check", async () => {
      queued += 1;
      await gate;
      return HttpResponse.json({ status: "queued", watch_id: 4, request_id: "test-receipt" }, { status: 202 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<WatchedDomains />);
  await user.dblClick(await screen.findByRole("button", { name: "立即检查" }));
  await waitFor(() => expect(queued).toBe(1));
  expect(screen.queryByText("已提交检查，完成后状态会自动更新")).not.toBeInTheDocument();
  acknowledge();
  expect(await screen.findByText("已提交检查，完成后状态会自动更新")).toBeInTheDocument();
  expect(queued).toBe(1);
});

test("网络断开时提示结果未确认，不自动重试或误报成功", async () => {
  let attempts = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/watchlist", () => HttpResponse.json({ items: [ENTRY], next_cursor: null })),
    http.post("*/api/v1/watchlist/4/check", () => { attempts += 1; return HttpResponse.error(); }),
  );
  const user = userEvent.setup();
  renderApp(<WatchedDomains />);
  await user.click(await screen.findByRole("button", { name: "立即检查" }));
  expect(await screen.findByText(/未收到检查提交确认/)).toBeInTheDocument();
  expect(screen.queryByText("已提交检查，完成后状态会自动更新")).not.toBeInTheDocument();
  expect(attempts).toBe(1);
});
