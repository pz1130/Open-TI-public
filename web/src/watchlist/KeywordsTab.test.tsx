import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import type { Schemas } from "../api/client";
import WatchlistPage from "../pages/WatchlistPage";
import { CONFIG_RULES, ME_ANALYST, ME_CONFIG_ANALYST, ME_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

const KEYWORDS: Schemas["DomainKeywordsOut"] = {
  version: 3, short_token_max_len: 4,
  brand: [
    { value: "sbr", findings_30d: 42, last_seen: "2026-10-15T01:00:00Z" },
    { value: "orbitbank", findings_30d: 0, last_seen: null },
  ],
  restricted: [{ value: "orbit", findings_30d: 17, last_seen: "2026-10-14T01:00:00Z", affixes: ["fund", "bank"] }],
  official: [{ value: "sbr.int", findings_30d: null, last_seen: null }],
  lookalike: ["sbrbank.com"],
  last_runs: { crtsh: { status: "ok", started_at: "2026-10-15T00:00:00Z", ended_at: "2026-10-15T00:05:00Z", items: 12 }, dnstwist: null },
};
const CHANGE: Schemas["KeywordChangeOut"] = {
  version: 4, changed: true,
  backfill: {
    crtsh: { status: "queued", reason: null, next_allowed_at: null, run_id: null },
    dnstwist: { status: "too_soon", reason: null, next_allowed_at: "2026-10-15T12:00:00Z", run_id: null },
  },
};

function useKeywords(me: Schemas["Me"]) {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(me)),
    http.get("*/api/v1/watchlist/keywords", () => HttpResponse.json(KEYWORDS)),
  );
}

test("默认显示关键词标签：统计、回溯状态，可切换到监视域名", async () => {
  useKeywords(ME_ANALYST);
  server.use(http.get("*/api/v1/watchlist", () => HttpResponse.json({ items: [], next_cursor: null, total: 0 })));
  const user = userEvent.setup();
  renderApp(<WatchlistPage />);
  expect(await screen.findByText("42")).toBeInTheDocument();
  expect(screen.getByText("sbr")).toBeInTheDocument();
  expect(screen.getAllByText("—").length).toBeGreaterThan(0); // 统计超时
  expect(screen.getByText("fund")).toBeInTheDocument();
  expect(screen.getByText("sbrbank.com")).toBeInTheDocument();
  expect(screen.getByText("尚未运行")).toBeInTheDocument();
  expect(screen.getByText("12 条", { exact: false })).toBeInTheDocument();
  await user.click(screen.getByText("监视域名"));
  expect(await screen.findByText("加入监视")).toBeInTheDocument();
});

test("添加品牌词：短词提示、试跑草稿、保存后提示版本与回溯", async () => {
  useKeywords(ME_CONFIG_ANALYST);
  let validated: unknown = null;
  let tested: unknown = null;
  let added: unknown = null;
  server.use(
    http.get("*/api/v1/config/rules", () => HttpResponse.json(CONFIG_RULES)),
    http.post("*/api/v1/config/rules/validate", async ({ request }) => {
      validated = await request.json();
      return HttpResponse.json({ ok: true, yaml: "draft: yes\n", data: null, errors: [] });
    }),
    http.post("*/api/v1/rules/test", async ({ request }) => {
      tested = await request.json();
      return HttpResponse.json({ source: "draft", project: "sbr", text_hits: [], domains: [
        { input: "sbrx-pay.top", status: "match", domain: "sbrx-pay.top", registered: "sbrx-pay.top", reasons: [{ reason: "brand_label", token: "sbrx" }] },
      ] });
    }),
    http.post("*/api/v1/watchlist/keywords", async ({ request }) => {
      added = await request.json();
      return HttpResponse.json(CHANGE, { status: 201 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<WatchlistPage />);
  await screen.findByText("42");
  await user.click(screen.getAllByText("添加")[0]);
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText("关键词"), "sbrx");
  expect(within(dialog).getByText(/不超过 4 个字符的短词/)).toBeInTheDocument();
  await user.type(within(dialog).getByLabelText("试跑：粘贴样例域名，每行一个"), "sbrx-pay.top");
  await user.click(within(dialog).getByText("试跑"));
  expect(await within(dialog).findByText("命中")).toBeInTheDocument();
  expect(within(dialog).getByText("brand_label:sbrx")).toBeInTheDocument();
  expect((validated as { data: { domains: { brand_tokens: string[] } } }).data.domains.brand_tokens).toEqual(["sbr", "sbrx"]);
  expect(tested).toEqual({ draft_yaml: "draft: yes\n", domains: ["sbrx-pay.top"], text: "" });
  await user.click(within(dialog).getByText("提交"));
  await waitFor(() => expect(added).toEqual({ kind: "brand", value: "sbrx", affixes: [] }));
  expect(await screen.findByText(/已保存为 v4；crt.sh 已安排回溯；dnstwist 距上次运行太近/)).toBeInTheDocument();
});

test("修改受限品牌词的词缀；删除要确认", async () => {
  useKeywords(ME_CONFIG_ANALYST);
  let removed = "";
  let affixes: unknown = null;
  server.use(
    http.put("*/api/v1/watchlist/keywords/restricted/orbit", async ({ request }) => {
      affixes = await request.json();
      return HttpResponse.json({ ...CHANGE, backfill: {} });
    }),
    http.delete("*/api/v1/watchlist/keywords/:kind/:value", ({ params }) => {
      removed = `${String(params.kind)}/${String(params.value)}`;
      return HttpResponse.json({ ...CHANGE, backfill: {} });
    }),
  );
  const user = userEvent.setup();
  renderApp(<WatchlistPage />);
  await screen.findByText("42");
  await user.click(screen.getByText("改词缀"));
  const dialog = (await screen.findByText("orbit 的词缀")).closest(".ant-modal") as HTMLElement;
  await user.type(dialog.querySelector("input") as HTMLInputElement, "coin{enter}");
  await user.click(within(dialog).getByText("保存修改"));
  await waitFor(() => expect(affixes).toEqual({ affixes: ["fund", "bank", "coin"] }));
  const row = screen.getByText("orbitbank").closest("tr") as HTMLElement;
  await user.click(within(row).getByText("删除"));
  expect(await screen.findByText("已发现的域名和告警会保留，以后不再按这个词匹配新域名。")).toBeInTheDocument();
  await user.click(screen.getByText("确定"));
  await waitFor(() => expect(removed).toBe("brand/orbitbank"));
});

test("查看命中域名，并把误报设为合法第三方", async () => {
  useKeywords(ME_CONFIG_ANALYST);
  let added: unknown = null;
  server.use(
    http.get("*/api/v1/watchlist/keywords/brand/sbr/domains", () => HttpResponse.json({ total: 1, items: [
      { finding_id: 7, domain: "sbr-loans.com", score: 70, severity: "high", last_seen: "2026-10-15T01:00:00Z", alert_id: 3, alert_status: "open" },
    ] })),
    http.post("*/api/v1/watchlist/keywords", async ({ request }) => {
      added = await request.json();
      return HttpResponse.json({ ...CHANGE, backfill: {} }, { status: 201 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<WatchlistPage />);
  await screen.findByText("42");
  const row = screen.getByText("sbr").closest("tr") as HTMLElement;
  await user.click(within(row).getByText("查看域名"));
  expect((await screen.findByText("#3")).closest("a")).toHaveAttribute("href", "/alerts/3");
  await user.click(screen.getByText("设为合法第三方"));
  await user.click(await screen.findByText("确定"));
  await waitFor(() => expect(added).toEqual({ kind: "lookalike", value: "sbr-loans.com", affixes: [] }));
  expect(await screen.findByText("该域名还有未关闭的告警 #3，请到告警页处理")).toBeInTheDocument();
});

test("只读用户只能查看", async () => {
  useKeywords(ME_VIEWER);
  renderApp(<WatchlistPage />);
  await screen.findByText("42");
  expect(screen.getAllByText("查看域名").length).toBeGreaterThan(0);
  expect(screen.queryByText("添加")).not.toBeInTheDocument();
  expect(screen.queryByText("删除")).not.toBeInTheDocument();
  expect(screen.queryByText("立即回溯")).not.toBeInTheDocument();
});

test("保存品牌词后再添加官方域名，类别不会沿用上次选择", async () => {
  useKeywords(ME_CONFIG_ANALYST);
  server.use(http.post("*/api/v1/watchlist/keywords", () => HttpResponse.json({ ...CHANGE, backfill: {} }, { status: 201 })));
  const user = userEvent.setup();
  renderApp(<WatchlistPage />);
  await screen.findByText("42");
  await user.click(screen.getAllByText("添加")[0]);
  let dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText("关键词"), "newbrand");
  await user.click(within(dialog).getByText("提交"));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await user.click(screen.getAllByText("添加")[2]);
  dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText("官方域名", { exact: true })).toBeInTheDocument();
  expect(within(dialog).getByLabelText("关键词")).toHaveValue("");
});

test("规则损坏的错误会提示去配置页修复", async () => {
  useKeywords(ME_CONFIG_ANALYST);
  server.use(http.post("*/api/v1/watchlist/keywords", () => HttpResponse.json({ detail: { reason: "rules_invalid" } }, { status: 409 })));
  const user = userEvent.setup();
  renderApp(<WatchlistPage />);
  await screen.findByText("42");
  await user.click(screen.getAllByText("添加")[0]);
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText("关键词"), "newbrand");
  await user.click(within(dialog).getByText("提交"));
  expect(await screen.findByText(/当前规则无法解析，请到配置页修复/)).toBeInTheDocument();
});

test("关键词和合法第三方列表分页，并允许选择每页条数", async () => {
  useKeywords(ME_CONFIG_ANALYST);
  server.use(http.get("*/api/v1/watchlist/keywords", () => HttpResponse.json({
    ...KEYWORDS,
    brand: Array.from({ length: 21 }, (_, i) => ({ value: `brand${i}`, findings_30d: 0, last_seen: null })),
    lookalike: Array.from({ length: 21 }, (_, i) => `legit${i}.com`),
  })));
  const user = userEvent.setup();
  renderApp(<WatchlistPage />);
  const brand = (await screen.findByText("brand0")).closest(".ant-card") as HTMLElement;
  const legit = screen.getByText("legit0.com").closest(".ant-card") as HTMLElement;
  expect(within(brand).queryByText("brand20")).not.toBeInTheDocument();
  expect(within(legit).queryByText("legit20.com")).not.toBeInTheDocument();
  await user.click(brand.querySelector('[title="2"]') as HTMLElement);
  expect(await within(brand).findByText("brand20")).toBeInTheDocument();
  await user.click(legit.querySelector('[title="2"]') as HTMLElement);
  expect(await within(legit).findByText("legit20.com")).toBeInTheDocument();
  await user.click(brand.querySelector(".ant-pagination-options-size-changer .ant-select-selector") as HTMLElement);
  await user.click(await screen.findByText("50 条/页"));
  expect(within(brand).getByText("brand0")).toBeInTheDocument();
  expect(within(brand).getByText("brand20")).toBeInTheDocument();
});
