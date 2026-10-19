import { browser } from "../api/hooks";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { AppRoutes } from "../App";
import { ME_ANALYST } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("未登录时显示登录页，登录成功后进入应用", async () => {
  let loggedIn = false;
  server.use(
    http.get("*/api/v1/alerts", () => HttpResponse.json({ items: [], next_cursor: null })),
    http.get("*/api/v1/auth/me", () =>
      loggedIn ? HttpResponse.json(ME_ANALYST) : new HttpResponse(null, { status: 401 }),
    ),
    http.post("*/api/v1/auth/login", async ({ request }) => {
      expect(request.headers.get("X-Requested-With")).toBe("opti");
      const body = (await request.json()) as { username: string; password: string };
      if (body.password !== "correct horse battery staple") return new HttpResponse(null, { status: 401 });
      loggedIn = true;
      return HttpResponse.json(ME_ANALYST);
    }),
  );
  const user = userEvent.setup();
  renderApp(<AppRoutes />);
  await user.type(await screen.findByLabelText("用户名"), "alice");
  await user.type(screen.getByLabelText("口令"), "wrong password!");
  await user.click(screen.getByRole("button", { name: "登录" }));
  expect(await screen.findByText("用户名或口令错误，或账号已被临时锁定")).toBeInTheDocument();
  await user.clear(screen.getByLabelText("口令"));
  await user.type(screen.getByLabelText("口令"), "correct horse battery staple");
  await user.click(screen.getByRole("button", { name: "登录" }));
  expect(await screen.findByText("Alice Analyst")).toBeInTheDocument();
});

test("切换到英文并记住选择", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts", () => HttpResponse.json({ items: [], next_cursor: null })),
  );
  const user = userEvent.setup();
  renderApp(<AppRoutes />);
  await user.click(await screen.findByText("English"));
  expect(await screen.findByTitle("Open account menu")).toBeInTheDocument();
  expect(screen.getByTitle("Collapse sidebar")).toBeInTheDocument();
  expect(screen.getByRole("navigation", { name: "Nav" })).toBeInTheDocument();
  expect(screen.getByLabelText("Dark theme")).toBeInTheDocument();
  await user.click(screen.getByTitle("Open account menu"));
  expect(await screen.findByText("Log out")).toBeInTheDocument();
  expect(window.localStorage.getItem("opti.lang")).toBe("en-US");
});

test("启用单点登录时显示登录按钮，应急账号折叠", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => new HttpResponse(null, { status: 401 })),
    http.get("*/api/v1/auth/providers", () => HttpResponse.json({ local: true, oidc: true, oidc_label: "Example SSO" })),
  );
  const user = userEvent.setup();
  renderApp(<AppRoutes />, { route: "/alerts/7" });
  const sso = await screen.findByRole("link", { name: "使用 Example SSO 登录" });
  expect(sso).toHaveAttribute("href", "/api/v1/auth/oidc/start?next=%2Falerts%2F7");
  expect(screen.queryByLabelText("用户名")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "使用应急账号登录" }));
  expect(await screen.findByLabelText("用户名")).toBeInTheDocument();
});

test("显示单点登录失败原因", async () => {
  server.use(http.get("*/api/v1/auth/me", () => new HttpResponse(null, { status: 401 })));
  renderApp(<AppRoutes />, { route: "/?login_error=no_role" });
  expect(await screen.findByText("你的账号没有分配本平台的角色，请联系管理员")).toBeInTheDocument();
});

test("单点登录会话登出后跳到身份提供方登出", async () => {
  const go = vi.spyOn(browser, "go").mockImplementation(() => {});
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_ANALYST, auth_source: "oidc" })),
    http.get("*/api/v1/alerts", () => HttpResponse.json({ items: [], next_cursor: null })),
    http.post("*/api/v1/auth/logout", () => HttpResponse.json({ logout_url: "https://idp.example/logout?client_id=opti" })),
  );
  const user = userEvent.setup();
  renderApp(<AppRoutes />);
  await user.click(await screen.findByTitle("展开账号菜单"));
  await user.click(await screen.findByText("退出登录"));
  await waitFor(() => expect(go).toHaveBeenCalledWith("https://idp.example/logout?client_id=opti"));
});
