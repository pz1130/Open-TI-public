import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import AuditLogPage from "./AuditLogPage";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("查看审计日志并校验完整性", async () => {
  server.use(
    http.get("*/api/v1/audit-logs", () =>
      HttpResponse.json({
        items: [{ id: 9, ts: "2026-10-02T08:00:00Z", actor: "alice", action: "alert.feedback", target_type: "alert",
                  target_id: "7", detail: { verdict: "false_positive" }, ip: "10.0.0.8", request_id: "r1" }],
        next_cursor: null,
      }),
    ),
    http.get("*/api/v1/audit-logs/verify", () =>
      HttpResponse.json({ ok: false, first_broken_id: 9, checked_at: "2026-10-02T09:00:00Z" }),
    ),
  );
  const user = userEvent.setup();
  renderApp(<AuditLogPage />);
  expect(await screen.findByText("alert.feedback")).toBeInTheDocument();
  expect(screen.getByText("alert#7")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "校验完整性" }));
  expect(await screen.findByText("从第 9 条记录开始不一致，日志可能被篡改")).toBeInTheDocument();
});
