import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import TicketsTab from "./TicketsTab";
import type { Schemas } from "../api/client";
import { CONFIG_ALERTING, CONFIG_STATUS, CONFIG_TICKETS, ME_CONFIG_ADMIN } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("save status mapping and signing key together", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_CONFIG_ADMIN)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/config/tickets", () => HttpResponse.json(CONFIG_TICKETS)),
    http.get("*/api/v1/config/alerting", () => HttpResponse.json(CONFIG_ALERTING)),
    http.get("*/api/v1/config/tickets/secrets", () => HttpResponse.json({ encryption_key: true, secrets: [
      { name: "signing_key", set: false, hint: null, source: "none", updated_by: null, updated_at: null },
      { name: "webhook_url", set: true, hint: null, source: "env", updated_by: null, updated_at: null },
    ] })),
    http.put("*/api/v1/config/tickets", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json(CONFIG_TICKETS);
    }),
  );
  const user = userEvent.setup();
  renderApp(<TicketsTab />);
  expect(await screen.findByText("https://ti.example/api/v1/integrations/tickets")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "添加映射" }));
  const statuses = screen.getAllByLabelText("工单状态");
  await user.type(statuses[statuses.length - 1], "wontfix");
  await user.type(screen.getByLabelText("签名密钥"), "s".repeat(32));
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).toMatchObject({
    data: { status_map: { resolved: "closed", wontfix: "closed" } },
    secrets: { signing_key: "s".repeat(32) },
  }));
});

const JIRA_TICKETS: Schemas["ConfigOut"] = {
  ...CONFIG_TICKETS,
  data: { ...CONFIG_TICKETS.data, mode: "jira", include_accounts: false, proxy: null, servicenow: null,
    jira: { base_url: "https://acme.atlassian.net", email: "ti@acme.org", project_key: "SEC", issue_type: "Task", priority_map: {}, extra_fields: {} } },
};

function jiraServer(test: () => ReturnType<typeof HttpResponse.json>, onSave: (body: Record<string, unknown>) => void) {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_CONFIG_ADMIN)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/config/tickets", () => HttpResponse.json(JIRA_TICKETS)),
    http.get("*/api/v1/config/alerting", () => HttpResponse.json(CONFIG_ALERTING)),
    http.get("*/api/v1/config/tickets/secrets", () => HttpResponse.json({ encryption_key: true, secrets: [
      { name: "jira_api_token", set: true, hint: "…abcd", source: "db", updated_by: "ops", updated_at: null },
    ] })),
    http.post("*/api/v1/config/tickets/test", test),
    http.put("*/api/v1/config/tickets", async ({ request }) => {
      onSave((await request.json()) as Record<string, unknown>);
      return HttpResponse.json(JIRA_TICKETS);
    }),
  );
}

test("Jira：保存优先级与附加字段，隐藏回调地址与状态映射", async () => {
  let body: Record<string, unknown> | null = null;
  jiraServer(() => HttpResponse.json({ ok: true, kind: null, detail: null }), (b) => { body = b; });
  const user = userEvent.setup();
  renderApp(<TicketsTab />);
  await user.type(await screen.findByLabelText("严重级优先级"), "Highest");
  await user.click(screen.getByRole("button", { name: "添加字段" }));
  await user.type(screen.getByLabelText("字段名"), "labels");
  await user.type(screen.getByLabelText("值"), '[["drp"]'); // userEvent 里 [[ 表示字面量 [
  expect(screen.queryByText("工单系统回调地址：")).not.toBeInTheDocument();
  expect(screen.queryByText("状态映射（工单状态 → 告警状态）")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).toMatchObject({
    data: { mode: "jira", status_map: { resolved: "closed" },
      jira: { project_key: "SEC", priority_map: { critical: "Highest" }, extra_fields: { labels: ["drp"] } } },
  }));
});

test("测试连接显示结果", async () => {
  let ok = true;
  jiraServer(() => HttpResponse.json(ok ? { ok: true, kind: null, detail: null }
    : { ok: false, kind: "auth", detail: "ticket system auth: HTTP 401" }), () => {});
  const user = userEvent.setup();
  renderApp(<TicketsTab />);
  await user.click(await screen.findByRole("button", { name: "测试连接" }));
  expect(await screen.findByText("连接成功")).toBeInTheDocument();
  ok = false;
  await user.click(screen.getByRole("button", { name: "测试连接" }));
  expect(await screen.findByText("连接失败：ticket system auth: HTTP 401")).toBeInTheDocument();
});

test("切换到 Webhook 保存时保留 Jira 段", async () => {
  let body: Record<string, unknown> | null = null;
  jiraServer(() => HttpResponse.json({ ok: true, kind: null, detail: null }), (b) => { body = b; });
  const user = userEvent.setup();
  renderApp(<TicketsTab />);
  await screen.findByLabelText("严重级优先级");
  await user.click(screen.getByRole("radio", { name: "Webhook" }));
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).toMatchObject({
    data: { mode: "webhook", status_map: { resolved: "closed" }, jira: { base_url: "https://acme.atlassian.net", project_key: "SEC" } },
  }));
});
