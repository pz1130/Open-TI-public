import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import TakedownsPage from "./TakedownsPage";
import type { Schemas } from "../api/client";
import { ME_RESPONDER, TAKEDOWN } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

function mock(td: Schemas["TakedownOut"], onMove?: (body: unknown) => void) {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_RESPONDER)),
    http.get("*/api/v1/takedowns", () => HttpResponse.json({ items: [td], next_cursor: null })),
    http.get("*/api/v1/takedowns/stats", () => HttpResponse.json({ by_state: { [td.state]: 1 }, mttr_hours: null, targets: [] })),
    http.get(`*/api/v1/takedowns/${td.id}`, () =>
      HttpResponse.json({
        takedown: td,
        events: [{ ts: "2026-10-03T00:00:00Z", actor: td.created_by, from_state: null, to_state: "draft", note: "" }],
        escalation: [],
      }),
    ),
    http.post(`*/api/v1/takedowns/${td.id}/transition`, async ({ request }) => {
      onMove?.(await request.json());
      return HttpResponse.json({ ...td, state: "approved", approved_by: ME_RESPONDER.username });
    }),
  );
}

test("审批他人起草的投诉", async () => {
  let moved: unknown = null;
  mock(TAKEDOWN, (body) => (moved = body));
  const user = userEvent.setup();
  renderApp(<TakedownsPage />, { route: "/takedowns?id=5" });
  expect(await screen.findByDisplayValue("滥用投诉：sbr-loans[.]com")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "审批" }));
  await waitFor(() => expect(moved).toEqual({ to: "approved", note: "", external_ref: null }));
});

test("不能审批自己起草的投诉", async () => {
  mock({ ...TAKEDOWN, created_by: ME_RESPONDER.username });
  renderApp(<TakedownsPage />, { route: "/takedowns?id=5" });
  expect(await screen.findByText("这是你起草的投诉，需要另一位有审批权限的人审批")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "审批" })).not.toBeInTheDocument();
});

test("审批后可下载 .eml 并标记已提交", async () => {
  let moved: unknown = null;
  mock({ ...TAKEDOWN, state: "approved", approved_by: "dave" }, (body) => (moved = body));
  const user = userEvent.setup();
  renderApp(<TakedownsPage />, { route: "/takedowns?id=5" });
  expect(await screen.findByRole("link", { name: /\.eml/ })).toHaveAttribute("href", "/api/v1/takedowns/5/eml");
  await user.type(screen.getByLabelText("对方工单号"), "CASE-9");
  await user.click(screen.getByRole("button", { name: "标记为已提交" }));
  await waitFor(() => expect(moved).toEqual({ to: "submitted", note: "", external_ref: "CASE-9" }));
});
