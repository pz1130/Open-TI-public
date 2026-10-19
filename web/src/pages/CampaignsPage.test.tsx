import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import CampaignsPage from "./CampaignsPage";
import { ME_ANALYST } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

export const CAMPAIGN = {
  id: 5, state: "candidate", name: null, label_value: "sbr-a.top", member_count: 3, pending_count: 0,
  active_alerts: 2, top_severity: "high", signal_kinds: ["html_sha256", "ip"], updated_at: "2026-10-08T08:00:00Z",
};

test("按状态切换列表并显示默认名", async () => {
  const states: string[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/campaigns", ({ request }) => {
      const state = new URL(request.url).searchParams.get("state") ?? "";
      states.push(state);
      const items = state === "confirmed" ? [{ ...CAMPAIGN, id: 6, state: "confirmed", name: "贷款诈骗团伙", pending_count: 1 }] : [CAMPAIGN];
      return HttpResponse.json({ items, total: items.length });
    }),
  );
  const user = userEvent.setup();
  renderApp(<CampaignsPage />);
  expect(await screen.findByRole("link", { name: "sbr-a.top 等 3 个" })).toHaveAttribute("href", "/campaigns/5");
  expect(screen.getByText("页面 HTML")).toBeInTheDocument();
  expect(screen.getByText("IP 地址")).toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: "已确认" }));
  expect(await screen.findByRole("link", { name: "贷款诈骗团伙" })).toBeInTheDocument();
  expect(screen.getByText(/1 个待确认/)).toBeInTheDocument();
  expect(states).toEqual(["candidate", "confirmed"]);
});
