import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { Route, Routes } from "react-router";
import CampaignDetailPage from "./CampaignDetailPage";
import { ME_ANALYST, ME_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

const MEMBER = {
  finding_id: 1, entity_type: "domain", value: "sbr-a.top", state: "member",
  signals: [{ kind: "ip", value: "93.184.216.34", with_finding: 2 }],
  alert_id: 11, severity: "high", status: "open", assignee: null, verdict: null, takedown_state: null,
  added_at: "2026-10-08T08:00:00Z",
};
const DETAIL = {
  campaign: {
    id: 5, state: "confirmed", name: null, label_value: "sbr-a.top", member_count: 2, pending_count: 1,
    active_alerts: 2, top_severity: "high", signal_kinds: ["ip"], updated_at: "2026-10-08T08:00:00Z",
  },
  note: "", confirmed_at: "2026-10-08T08:00:00Z", confirmed_by: "alice",
  ignored: [{ kind: "ip", value: "104.16.0.1", count: 37 }],
  members: [
    MEMBER,
    { ...MEMBER, finding_id: 2, value: "sbr-b.top", alert_id: 12, signals: [{ kind: "ip", value: "93.184.216.34", with_finding: 1 }] },
    { ...MEMBER, finding_id: 3, value: "sbr-c.top", alert_id: 13, state: "pending" },
  ],
};

function renderDetail() {
  return renderApp(
    <Routes>
      <Route path="campaigns/:id" element={<CampaignDetailPage />} />
    </Routes>,
    { route: "/campaigns/5" },
  );
}

test("显示成员、依据与忽略值，接受待确认成员并批量研判", async () => {
  let decided: unknown = null;
  let bulk: unknown = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/campaigns/5", () => HttpResponse.json(DETAIL)),
    http.post("*/api/v1/campaigns/5/members/3", async ({ request }) => {
      decided = await request.json();
      return HttpResponse.json(DETAIL.campaign);
    }),
    http.post("*/api/v1/campaigns/5/bulk", async ({ request }) => {
      bulk = await request.json();
      return HttpResponse.json({ updated: [11, 12], skipped: 0 });
    }),
  );
  const user = userEvent.setup();
  renderDetail();
  expect(await screen.findByText("sbr-a.top 等 2 个")).toBeInTheDocument();
  expect(screen.getByText(/104\.16\.0\.1/)).toBeInTheDocument();
  expect(screen.getByText(/37 个发现/)).toBeInTheDocument();
  expect(screen.getAllByText(/与 sbr-b\.top 共用IP 地址：93\.184\.216\.34/).length).toBeGreaterThan(0);

  const pending = screen.getByTestId("campaign-pending");
  await user.click(within(pending).getByRole("button", { name: "接受" }));
  await waitFor(() => expect(decided).toEqual({ decision: "accept" }));

  await user.click(screen.getByRole("button", { name: "批量研判结论" }));
  await user.click(await screen.findByLabelText("误报"));
  await user.type(screen.getByLabelText("原因"), "同一团伙");
  expect(screen.getByText("将影响 2 条未关闭告警，确定执行？")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "执行" }));
  await waitFor(() => expect(bulk).toEqual({ action: "verdict", verdict: "false_positive", reason: "同一团伙" }));
});

test("无研判权限时只读", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_VIEWER, permissions: [...ME_VIEWER.permissions, "evidence:read"] })),
    http.get("*/api/v1/campaigns/5", () => HttpResponse.json(DETAIL)),
  );
  renderDetail();
  expect(await screen.findByText("sbr-a.top 等 2 个")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "批量研判结论" })).toBeNull();
  expect(screen.queryByRole("button", { name: "接受" })).toBeNull();
  expect(screen.queryByRole("button", { name: "退回候选" })).toBeNull();
});

test("退回候选须二次确认，批量研判未选结论时不提交", async () => {
  const patched: unknown[] = [];
  let bulkCalls = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/campaigns/5", () => HttpResponse.json(DETAIL)),
    http.patch("*/api/v1/campaigns/5", async ({ request }) => {
      patched.push(await request.json());
      return HttpResponse.json({ ...DETAIL.campaign, state: "candidate" });
    }),
    http.post("*/api/v1/campaigns/5/bulk", () => {
      bulkCalls += 1;
      return HttpResponse.json({ updated: [], skipped: 0 });
    }),
  );
  const user = userEvent.setup();
  renderDetail();
  await user.click(await screen.findByRole("button", { name: "退回候选" }));
  expect(await screen.findByText(/退回后由系统重算接管/)).toBeInTheDocument();
  expect(patched).toEqual([]);
  await user.click(screen.getByRole("button", { name: /确\s*定|OK/ }));
  await waitFor(() => expect(patched).toEqual([{ state: "candidate" }]));

  await user.click(screen.getByRole("button", { name: "批量研判结论" }));
  await user.click(await screen.findByRole("button", { name: "执行" }));
  expect(await screen.findByText(/请输入|请选择|required/i)).toBeInTheDocument();
  expect(bulkCalls).toBe(0);
});
