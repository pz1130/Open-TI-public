import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import SuppressionsPage from "./SuppressionsPage";
import { ME_ANALYST } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

const RULE = {
  id: 2, kind: "registered_domain", value: "sbrbank.com", reason: "SBR Bank PLC", created_by: "alice",
  source_alert_id: 7, created_at: "2026-10-02T00:00:00Z", expires_at: null, revoked_at: null, active: true,
};

test("列出、新建与撤销规则", async () => {
  let created: unknown = null;
  let revoked = false;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/suppressions", () => HttpResponse.json(revoked ? [] : [RULE])),
    http.post("*/api/v1/suppressions", async ({ request }) => {
      created = await request.json();
      return HttpResponse.json({ ...RULE, id: 3 }, { status: 201 });
    }),
    http.delete("*/api/v1/suppressions/2", () => {
      revoked = true;
      return new HttpResponse(null, { status: 204 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SuppressionsPage />);
  expect(await screen.findByText("sbrbank.com")).toBeInTheDocument();
  expect(screen.getByText("可注册域（含子域）")).toBeInTheDocument();

  await user.click(await screen.findByRole("button", { name: "新建规则" }));
  await user.click(await screen.findByLabelText("主机名"));
  await user.type(screen.getByLabelText("值"), "login.sbr-loans.com");
  await user.type(screen.getByLabelText("原因"), "供应商测试");
  await user.click(screen.getByRole("button", { name: "提交" }));
  await waitFor(() =>
    expect(created).toEqual({ kind: "domain", value: "login.sbr-loans.com", reason: "供应商测试", expires_days: null }),
  );

  await user.click(screen.getByRole("button", { name: "撤销" }));
  await user.click(await screen.findByRole("button", { name: "确定" }));
  await waitFor(() => expect(revoked).toBe(true));
});
