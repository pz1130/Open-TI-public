import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import ConnectorsPage from "./ConnectorsPage";
import { CONNECTORS, ME_ADMIN, ME_ANALYST } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("已启用但未批准的连接器显示阻止原因", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/connectors", () => HttpResponse.json([{
      ...CONNECTORS[0], enabled: true, runnable: false, health: "blocked",
      reason: "license_not_approved：法务尚未批准", license_approved: false,
    }])),
  );
  renderApp(<ConnectorsPage />);
  expect(await screen.findByText("暂不可运行")).toBeInTheDocument();
  expect(screen.getByText("license_not_approved：法务尚未批准")).toBeInTheDocument();
  expect(screen.queryByText("停用")).toBeNull();
});

test("显示目录、合规与健康状态，展开看凭据，按名称筛选", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
  );
  const user = userEvent.setup();
  renderApp(<ConnectorsPage />);
  expect(await screen.findByText("crt.sh")).toBeInTheDocument();
  expect(screen.getByText("已批准 · CT-PUBLIC")).toBeInTheDocument();
  expect(screen.getByText("未批准")).toBeInTheDocument();
  expect(screen.getByText("运行失败")).toBeInTheDocument();
  expect(screen.getByText("等待上报")).toBeInTheDocument();
  expect(screen.getByText("24 小时 3 次 / 失败 1 次")).toBeInTheDocument();
  const expand = screen.getAllByRole("button", { name: /展开行|Expand row/ });
  await user.click(expand[1]);
  expect(await screen.findByText("api_key：由采集节点管理")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "服务条款" })).toHaveAttribute("rel", "noopener noreferrer");
  await user.type(screen.getByPlaceholderText("按名称或 ID 筛选"), "urlscan{Enter}");
  expect(screen.queryByText("crt.sh")).toBeNull();
});

test("管理员在页面保存参数和凭据，页面不会回显密钥", async () => {
  let submitted: unknown;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ADMIN)),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
    http.get("*/api/v1/connectors/urlscan/config", () => HttpResponse.json({
      id: "urlscan", darkweb: false, enabled: false, plan: "free", plans: ["free", "pro"], config: { max_pages: 2 },
      config_schema: { type: "object", properties: { max_pages: { type: "integer", title: "Pages" } } },
      credentials: [{ name: "api_key", required: false, configured: false }],
      license_approved: false, license_ref: null, darkweb_approval_ref: null, encryption_key: true,
    })),
    http.put("*/api/v1/connectors/urlscan/config", async ({ request }) => {
      submitted = await request.json();
      return HttpResponse.json({});
    }),
  );
  const user = userEvent.setup();
  renderApp(<ConnectorsPage />);
  await screen.findByText("urlscan.io");
  await user.click(screen.getAllByRole("button", { name: "配置" })[1]);
  expect(await screen.findByText("Pages")).toBeInTheDocument();
  await user.click(screen.getByRole("switch", { name: "启用" }));
  await user.type(screen.getByLabelText("api_key"), "new-key");
  await user.click(screen.getByRole("button", { name: /关闭|close/i }));
  expect((await screen.findAllByText("有尚未保存的修改")).length).toBeGreaterThan(0);
  expect(submitted).toBeUndefined();
  await user.click(screen.getByRole("button", { name: "继续编辑" }));
  await user.click(screen.getByRole("button", { name: "保存配置" }));
  expect(await screen.findByText("配置已保存")).toBeInTheDocument();
  expect(submitted).toMatchObject({ enabled: true, plan: "free", config: { max_pages: 2 }, secrets: { api_key: "new-key" } });
  expect(screen.queryByText("new-key")).toBeNull();
});

test("合规官只能保存许可审批", async () => {
  let submitted: unknown;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_ANALYST, roles: ["compliance_officer"], permissions: ["connectors:read", "connectors:approve"] })),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
    http.get("*/api/v1/connectors/urlscan/config", () => HttpResponse.json({
      id: "urlscan", darkweb: false, enabled: true, plan: "free", plans: ["free"], config: {},
      config_schema: { type: "object" }, credentials: [], license_approved: false,
      license_ref: null, darkweb_approval_ref: null, encryption_key: true,
    })),
    http.put("*/api/v1/connectors/urlscan/approval", async ({ request }) => {
      submitted = await request.json();
      return HttpResponse.json({});
    }),
  );
  const user = userEvent.setup();
  renderApp(<ConnectorsPage />);
  await screen.findByText("urlscan.io");
  await user.click(screen.getAllByRole("button", { name: "配置" })[1]);
  expect(await screen.findByText("许可审批编号")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "保存配置" })).toBeNull();
  await user.click(screen.getByRole("switch", { name: "已批准" }));
  await user.type(screen.getByRole("textbox", { name: "许可审批编号" }), "LEGAL-1");
  await user.click(screen.getByRole("button", { name: "保存审批" }));
  expect(await screen.findByText("配置已保存")).toBeInTheDocument();
  expect(submitted).toMatchObject({ license_approved: true, license_ref: "LEGAL-1" });
});

const URLSCAN_CONFIG = {
  id: "urlscan", darkweb: false, enabled: true, plan: "free", plans: ["free"], config: {},
  config_schema: { type: "object" }, credentials: [{ name: "api_key", required: false, configured: true, problem: null }],
  license_approved: true, license_ref: "L-1", darkweb_approval_ref: null, encryption_key: true, version: 4,
};
const HISTORY = [
  { version: 4, created_by: "ops", created_at: "2026-10-13T08:00:00Z", note: null, restored_from: null,
    changed: ["enabled"], diff: "--- v2\n+++ v4\n-enabled: false\n+enabled: true\n", restorable: false },
  { version: 2, created_by: "ops", created_at: "2026-10-12T08:00:00Z", note: null, restored_from: null,
    changed: ["enabled", "config"], diff: "--- v0\n+++ v2\n", restorable: true },
];

test("历史标签：列出版本与改动，确认后只恢复参数", async () => {
  let restored: unknown;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ADMIN)),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
    http.get("*/api/v1/connectors/urlscan/config", () => HttpResponse.json(URLSCAN_CONFIG)),
    http.get("*/api/v1/connectors/urlscan/history", () => HttpResponse.json(HISTORY)),
    http.post("*/api/v1/connectors/urlscan/restore", async ({ request }) => {
      restored = await request.json();
      return HttpResponse.json({ ...URLSCAN_CONFIG, enabled: false, version: 5 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<ConnectorsPage />);
  await screen.findByText("urlscan.io");
  await user.click(screen.getAllByRole("button", { name: "配置" })[1]);
  await user.click(await screen.findByRole("tab", { name: "历史" }));
  expect(await screen.findByText("v4")).toBeInTheDocument();
  expect(screen.getAllByText("参数").length).toBeGreaterThan(0);
  expect(screen.getByText(/凭据改动不进版本记录/)).toBeInTheDocument();
  const restoreButtons = screen.getAllByRole("button", { name: "恢复参数到此版本" });
  expect(restoreButtons).toHaveLength(1); // 只有参数与当前不同的版本可以恢复
  await user.click(restoreButtons[0]);
  expect(await screen.findByText(/法务批准与凭据不变/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "确认恢复" }));
  expect(await screen.findByText("已恢复，当前为 v5")).toBeInTheDocument();
  expect(restored).toEqual({ version: 2 });
});

test("没有写权限时历史里看不到恢复按钮", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_ANALYST, roles: ["compliance_officer"], permissions: ["connectors:read", "connectors:approve"] })),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
    http.get("*/api/v1/connectors/urlscan/config", () => HttpResponse.json(URLSCAN_CONFIG)),
    http.get("*/api/v1/connectors/urlscan/history", () => HttpResponse.json(HISTORY)),
  );
  const user = userEvent.setup();
  renderApp(<ConnectorsPage />);
  await screen.findByText("urlscan.io");
  await user.click(screen.getAllByRole("button", { name: "配置" })[1]);
  await user.click(await screen.findByRole("tab", { name: "历史" }));
  expect(await screen.findByText("v2")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "恢复参数到此版本" })).toBeNull();
});

test("保存后显示版本号；凭据无法解密时提示重新填写", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ADMIN)),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
    http.get("*/api/v1/connectors/urlscan/config", () => HttpResponse.json({
      ...URLSCAN_CONFIG, credentials: [{ name: "api_key", required: false, configured: false, problem: "connectors:urlscan:api_key 无法解密：bad tag" }],
    })),
    http.put("*/api/v1/connectors/urlscan/config", () => HttpResponse.json({ ...URLSCAN_CONFIG, version: 5 })),
  );
  const user = userEvent.setup();
  renderApp(<ConnectorsPage />);
  await screen.findByText("urlscan.io");
  await user.click(screen.getAllByRole("button", { name: "配置" })[1]);
  expect(await screen.findByText("无法解密，请重新填写")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "保存配置" }));
  expect(await screen.findByText("配置已保存（v5）")).toBeInTheDocument();
});
