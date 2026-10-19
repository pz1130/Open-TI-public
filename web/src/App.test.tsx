import { screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { AppRoutes } from "./App";
import { ME_VIEWER } from "./test/fixtures";
import { renderApp } from "./test/render";
import { server } from "./test/server";

test("初始密码用户访问业务深链接仍只显示改密页，不读取业务数据", async () => {
  let reads = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_VIEWER, must_change_password: true })),
    http.get("*/api/v1/alerts", () => { reads += 1; return HttpResponse.json({ items: [] }); }),
  );
  renderApp(<AppRoutes />, { route: "/alerts" });
  expect(await screen.findByLabelText("当前密码")).toBeInTheDocument();
  expect(screen.getByText(/须先修改密码才能使用平台/)).toBeInTheDocument();
  expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  expect(reads).toBe(0);
});

test("普通用户直接访问管理深链接不会加载管理员接口", async () => {
  let reads = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_VIEWER, permissions: ["alerts:read"] })),
    http.get("*/api/v1/admin/users", () => { reads += 1; return HttpResponse.json({ items: [], total: 0 }); }),
  );
  renderApp(<AppRoutes />, { route: "/settings/users" });
  expect(await screen.findByText("页面不存在")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "配置" })).not.toBeInTheDocument();
  expect(reads).toBe(0);
});
