import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import ServicesTab from "./ServicesTab";
import { renderApp } from "../test/render";
import { server } from "../test/server";
import { SECTIONS } from "./sections";
import { can } from "../auth/perms";
import { ME_CONFIG_ADMIN, ME_CONFIG_VIEWER } from "../test/fixtures";

const JOB = { id: "a".repeat(32), services: ["api", "worker"], phase: "queued", requested_at: "2026-10-15T01:00:00Z", updated_at: "2026-10-15T01:00:00Z", completed_services: [], error: null };
const STATUS = { available: true, services: [{ name: "api", running: 1, containers: 1 }, { name: "worker", running: 1, containers: 1 }], operation: null, problem: null };

test("主密钥与服务维护属于管理员分组，普通用户不能进入", () => {
  const section = SECTIONS.find((s) => s.group === "admin")!;
  expect(section.items.map((item) => item.kind)).toContain("master_key");
  expect(section.items.map((item) => item.kind)).toContain("services");
  for (const item of section.items) {
    expect(can(ME_CONFIG_ADMIN, item.perm!)).toBe(true);
    expect(can(ME_CONFIG_VIEWER, item.perm!)).toBe(false);
  }
});

test("控制器未配置时解释升级部署并禁用重启", async () => {
  server.use(http.get("*/api/v1/admin/services", () => HttpResponse.json({ ...STATUS, available: false, problem: "not_configured" })));
  renderApp(<ServicesTab />);
  expect(await screen.findByText(/当前部署未启用 Web 重启/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "重启所选服务" })).toBeDisabled();
});

test("选择 worker，确认后只提交一次并显示执行状态", async () => {
  let operation: object | null = null;
  let body: unknown;
  server.use(
    http.get("*/api/v1/admin/services", () => HttpResponse.json({ ...STATUS, operation })),
    http.post("*/api/v1/admin/services/restart", async ({ request }) => {
      body = await request.json();
      operation = { ...JOB, services: ["worker"] };
      return HttpResponse.json(operation, { status: 202 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<ServicesTab />);
  await screen.findByRole("button", { name: "重启所选服务" });
  await user.click(screen.getByRole("checkbox", { name: "API 与 Web 页面" }));
  await user.click(screen.getByRole("button", { name: "重启所选服务" }));
  await user.click(await screen.findByRole("button", { name: "确定" }));
  await waitFor(() => expect(body).toEqual({ services: ["worker"], reason: "" }));
  expect(await screen.findByText("等待执行")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "重启所选服务" })).toBeDisabled();
});

test("API 暂时断线时保留重启状态，不再次提交", async () => {
  let dropped = false;
  let calls = 0;
  server.use(
    http.get("*/api/v1/admin/services", () => dropped ? HttpResponse.json({ detail: "unavailable" }, { status: 503 }) : HttpResponse.json(STATUS)),
    http.post("*/api/v1/admin/services/restart", () => { calls++; dropped = true; return HttpResponse.json(JOB, { status: 202 }); }),
  );
  const user = userEvent.setup();
  renderApp(<ServicesTab />);
  await user.click(await screen.findByRole("button", { name: "重启所选服务" }));
  await user.click(await screen.findByRole("button", { name: "确定" }));
  expect(await screen.findByText("API 正在重启，页面将自动重新连接。")).toBeInTheDocument();
  expect(screen.getByText("等待执行")).toBeInTheDocument();
  expect(calls).toBe(1);
});
