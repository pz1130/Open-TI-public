import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import ExposureCard from "./ExposureCard";
import { EXPOSURE, ME_ANALYST, ME_RESPONDER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("分析员看到泄露事件与数量，可以推给 IT，但看不到账户", async () => {
  let pushed = false;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts/7/exposure", () => HttpResponse.json(pushed ? { ...EXPOSURE, accounts_pending: 0 } : EXPOSURE)),
    http.post("*/api/v1/alerts/7/exposure/push", () => {
      pushed = true;
      return HttpResponse.json({ pushed: 2, channel: "webhook", ticket_ref: "IT-100" });
    }),
  );
  const user = userEvent.setup();
  renderApp(<ExposureCard alertId={7} />);
  expect(await screen.findByText("New Leak 2026")).toBeInTheDocument();
  expect(screen.getByText("Passwords")).toBeInTheDocument();
  expect(screen.getByText("2 / 2")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "查看账户" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "推送 2 个账户给 IT" }));
  expect(await screen.findByText("已推送 2 个账户（工单 IT-100）")).toBeInTheDocument();
});

test("处置人员可以查看受影响账户", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_RESPONDER)),
    http.get("*/api/v1/alerts/7/exposure", () => HttpResponse.json(EXPOSURE)),
    http.get("*/api/v1/alerts/7/exposure/accounts", () =>
      HttpResponse.json([
        { email: "alice@sbr.int", first_seen: "2026-10-03T00:00:00Z", last_seen: "2026-10-03T00:00:00Z", pushed_at: null },
      ]),
    ),
  );
  const user = userEvent.setup();
  renderApp(<ExposureCard alertId={7} />);
  await user.click(await screen.findByRole("button", { name: "查看账户" }));
  expect(await screen.findByText("alice@sbr.int")).toBeInTheDocument();
  expect(screen.getByText("未推送")).toBeInTheDocument();
});
