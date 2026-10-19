import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { Route, Routes } from "react-router";
import AlertDetailPage from "./AlertDetailPage";
import { ALERT_DETAIL, ME_ANALYST, ME_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

function renderDetail() {
  return renderApp(
    <Routes>
      <Route path="alerts/:id" element={<AlertDetailPage />} />
    </Routes>,
    { route: "/alerts/7" },
  );
}

test("显示评分构成、证据，并提交误报 + 抑制规则", async () => {
  let posted: unknown = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () => HttpResponse.json(ALERT_DETAIL)),
    http.post("*/api/v1/alerts/7/feedback", async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json({ ...ALERT_DETAIL.alert, status: "closed", triage_verdict: "false_positive" });
    }),
  );
  const user = userEvent.setup();
  renderDetail();
  expect(await screen.findByText("域名风险")).toBeInTheDocument();
  expect(screen.getByText("+40")).toBeInTheDocument();
  expect(screen.getByRole("img", { name: "截图" })).toHaveAttribute("src", "/api/v1/evidence/11/content");
  expect(screen.getByRole("link", { name: "下载（纯文本）" })).toHaveAttribute("href", "/api/v1/evidence/12/content");
  expect(screen.getAllByText("sbr-loans.com")[0].closest("a")).toBeNull();
  expect(screen.getByRole("link", { name: "T1583.001 Domains · 资源开发" })).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1583/001/");
  expect(screen.getByText("根据告警类别关联，尚未证实攻击技术")).toBeInTheDocument();
  await user.click(await screen.findByLabelText("误报")); // 等当前用户加载完、表单出现
  await user.click(await screen.findByLabelText("整个可注册域（含子域）"));
  await user.type(screen.getByLabelText("说明"), "供应商测试站");
  await user.click(screen.getByRole("button", { name: "提交" }));
  await waitFor(() =>
    expect(posted).toEqual({ verdict: "false_positive", reason: "供应商测试站", suppress: "registered_domain", suppress_days: null }),
  );
  expect(await screen.findByText("研判结论已提交")).toBeInTheDocument();
});

test("只读用户看不到研判表单与截图", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/alerts/7", () => HttpResponse.json({
      ...ALERT_DETAIL,
      enrichment: { screenshot: { data: {
        visual: { possible_matches: [{ reference: "机构主 Logo", distance: 0 }] },
        favicon: { hash: -123456, reference_matches: ["机构官网"] },
        ocr: { brand_terms: ["样本品牌"] },
      } } },
    })),
  );
  renderDetail();
  expect(await screen.findByText("域名风险")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "提交" })).toBeNull();
  expect(screen.queryByRole("img", { name: "截图" })).toBeNull();
  expect(screen.getByText("没有查看证据的权限")).toBeInTheDocument();
  expect(screen.queryByText("发现与机构 Logo 相似的图片")).toBeNull();
  expect(screen.queryByText("站点图标与机构参考图标指纹相同")).toBeNull();
  expect(screen.queryByText("截图文字识别命中品牌词")).toBeNull();
});

test("视觉相似线索仅在证据可见时提示人工核查", async () => {
  const detail = {
    ...ALERT_DETAIL,
    enrichment: {
      ...ALERT_DETAIL.enrichment,
      screenshot: { data: { visual: {
        method: "dhash64", threshold: 8, candidate_count: 1,
        possible_matches: [{ reference: "机构主 Logo", distance: 2, box: { x: 10, y: 20, width: 80, height: 60 } }],
      } } },
    },
  };
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () => HttpResponse.json(detail)),
  );
  renderDetail();
  expect(await screen.findByText("发现与机构 Logo 相似的图片")).toBeInTheDocument();
  expect(screen.getByText(/仅供人工核查/)).toBeInTheDocument();
});

test("显示站点图标精确匹配及人工关联边界", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () => HttpResponse.json({
      ...ALERT_DETAIL,
      enrichment: { screenshot: { data: { favicon: {
        method: "mmh3-rfc2045-base64", hash: -123456,
        reference_matches: ["机构官网"],
      } } } },
    })),
  );
  renderDetail();
  expect(await screen.findByText("站点图标与机构参考图标指纹相同")).toBeInTheDocument();
  expect(screen.getByText("mmh3：-123456")).toBeInTheDocument();
  expect(screen.getByText(/相同指纹不能单独证明/)).toBeInTheDocument();
});

test("截图 OCR 命中只作为人工核查线索", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () => HttpResponse.json({
      ...ALERT_DETAIL,
      enrichment: { screenshot: { data: { ocr: {
        method: "tesseract-eng+chi_sim-psm11", brand_terms: ["样本品牌"], char_count: 24,
      } } } },
    })),
  );
  renderDetail();
  expect(await screen.findByText("截图文字识别命中品牌词")).toBeInTheDocument();
  expect(screen.getByText("样本品牌")).toBeInTheDocument();
  expect(screen.getByText(/对照原始截图人工核查/)).toBeInTheDocument();
});

test("只向证据读者展示关联告警与匹配依据", async () => {
  const detail = {
    ...ALERT_DETAIL,
    related_alerts: [{
      id: 8, domain: "sbr-grants.top", severity: "high", status: "open",
      last_seen: "2026-10-02T08:00:00Z", signals: ["tls_sha256", "favicon_sha256"],
    }],
  };
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () => HttpResponse.json(detail)),
  );
  const view = renderDetail();
  expect(await screen.findByText("关联告警线索")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "#8" })).toHaveAttribute("href", "/alerts/8");
  expect(screen.getByText("TLS 证书 SHA-256 相同")).toBeInTheDocument();
  expect(screen.getByText("站点图标 SHA-256 相同")).toBeInTheDocument();
  view.unmount();
  server.use(http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)));
  renderDetail();
  expect(await screen.findByText("域名风险")).toBeInTheDocument();
  expect(screen.queryByText("关联告警线索")).toBeNull();
});

test("已被取代的告警只读", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () =>
      HttpResponse.json({ ...ALERT_DETAIL, alert: { ...ALERT_DETAIL.alert, status: "superseded" } }),
    ),
  );
  renderDetail();
  expect(await screen.findByText("该告警已被更高级别的告警取代，仅供查看")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "提交" })).toBeNull();
  expect(screen.queryByRole("button", { name: "关闭" })).toBeNull();
  expect(screen.queryByRole("button", { name: /上传截图/ })).toBeNull();
});

test("区分告警触发评分和最新观测评分", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/alerts/7", () => HttpResponse.json({
      ...ALERT_DETAIL,
      finding: { ...ALERT_DETAIL.finding, score: 50, score_breakdown: { base: 20, domain_risk: 30 } },
    })),
  );
  renderDetail();
  expect(await screen.findByText("告警触发评分")).toBeInTheDocument();
  expect(screen.getByText("评分构成反映最新观测，与告警触发时的评分快照不同。")).toBeInTheDocument();
  expect(screen.getAllByText("50")).toHaveLength(2);
  expect(screen.getByText("+30")).toBeInTheDocument();
});


test("URL 告警不提供抑制选项", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () =>
      HttpResponse.json({
        ...ALERT_DETAIL,
        entity_type: "url",
        alert: { ...ALERT_DETAIL.alert, domain: "https://sites.google.com/view/sbr-grants" },
      }),
    ),
  );
  const user = userEvent.setup();
  renderDetail();
  await user.click(await screen.findByLabelText("误报"));
  expect(screen.queryByLabelText("整个可注册域（含子域）")).toBeNull();
  expect(screen.getAllByText("https://sites.google.com/view/sbr-grants")[0].closest("a")).toBeNull();
});

test("显示举报描述与来源上下文", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () =>
      HttpResponse.json({
        ...ALERT_DETAIL,
        entity_type: "report",
        alert: { ...ALERT_DETAIL.alert, category: "reported_phishing", reasons: ["reported"] },
        finding: {
          ...ALERT_DETAIL.finding,
          category: "reported_phishing",
          score_breakdown: { base: 45, owned_signal: 15 },
          match: { signal: "reported", context: { description: "自称贷款专员，要求先交手续费", category: "loan" } },
        },
      }),
    ),
  );
  renderDetail();
  expect(await screen.findByText("自称贷款专员，要求先交手续费")).toBeInTheDocument();
  expect(screen.getByText("来源上下文")).toBeInTheDocument();
  expect(screen.getAllByText("被举报的钓鱼").length).toBeGreaterThan(0);
  expect(screen.getByText("机构自有信号")).toBeInTheDocument();
});

test("平台链接提示上传截图，上传后显示上传人", async () => {
  const detail = { ...ALERT_DETAIL, evidence: [], finding: { ...ALERT_DETAIL.finding, match: { platform: "linkedin" } } };
  let uploaded = false;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () =>
      HttpResponse.json(uploaded ? { ...detail, evidence: [{ ...ALERT_DETAIL.evidence[0], id: 30, kind: "upload", node_id: "upload",
        method: "analyst-upload", uploaded_by: "alice", original_sha256: "c".repeat(64) }] } : detail),
    ),
    http.post("*/api/v1/alerts/7/evidence", () => {
      uploaded = true;
      return HttpResponse.json({ ...ALERT_DETAIL.evidence[0], id: 30, kind: "upload" }, { status: 201 });
    }),
  );
  const user = userEvent.setup();
  renderDetail();
  expect(await screen.findByText("该链接属于平台名单，平台不会自动截图，请上传截图作为证据")).toBeInTheDocument();
  const input = screen.getByTestId("evidence-upload").querySelector("input[type=file]") as HTMLInputElement;
  await user.upload(input, new File([new Uint8Array([1])], "a.png", { type: "image/png" }));
  expect(await screen.findByText(/alice 上传/)).toBeInTheDocument();
});

test("显示所属活动", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7", () =>
      HttpResponse.json({
        ...ALERT_DETAIL,
        campaign: { id: 5, name: null, label_value: "sbr-loans.com", member_count: 4, state: "confirmed", member_state: "pending" },
      }),
    ),
  );
  renderDetail();
  expect(await screen.findByText("所属活动")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "sbr-loans.com 等 4 个" })).toHaveAttribute("href", "/campaigns/5");
  expect(screen.getByText("待确认")).toBeInTheDocument();
});

