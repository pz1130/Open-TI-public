import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, vi } from "vitest";
import { Route, Routes } from "react-router";
import AppLayout from "./AppLayout";
import type { Me } from "../api/hooks";
import { ME_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";

let restoreMedia: (() => void) | undefined;
afterEach(() => restoreMedia?.());

function navigationSize(initial: boolean) {
  let narrow = initial;
  const listeners = new Set<() => void>();
  const original = window.matchMedia;
  const spy = vi.spyOn(window, "matchMedia").mockImplementation((query) => query !== "(max-width: 900px)" ? original(query) : {
    ...original(query), get matches() { return narrow; },
    addEventListener: (_type: string, listener: EventListenerOrEventListenerObject) => { listeners.add(listener as () => void); },
    removeEventListener: (_type: string, listener: EventListenerOrEventListenerObject) => { listeners.delete(listener as () => void); },
  });
  restoreMedia = () => spy.mockRestore();
  return (next: boolean) => act(() => { narrow = next; listeners.forEach((listener) => listener()); });
}

function renderLayout(me: Me = ME_VIEWER, route = "/alerts") {
  return renderApp(<Routes><Route element={<AppLayout me={me} />}>
    {["alerts", "search", "dashboard", "settings"].map((path) => <Route key={path} path={path} element={<h1>{path} content</h1>} />)}
  </Route></Routes>, { route });
}

test("窄屏关闭的导航不可访问，打开后限制焦点，Esc 返回触发按钮", async () => {
  navigationSize(true);
  const user = userEvent.setup();
  const { container } = renderLayout();
  const side = container.querySelector("aside")!;
  const main = container.querySelector(".oti-main")!;
  const trigger = screen.getByRole("button", { name: "打开导航" });
  expect(side).toHaveAttribute("inert");
  expect(side).toHaveAttribute("aria-hidden", "true");
  expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  expect(trigger).toHaveAttribute("aria-expanded", "false");
  await user.click(trigger);
  const dialog = screen.getByRole("dialog");
  expect(dialog).toHaveAttribute("aria-modal", "true");
  expect(dialog).not.toHaveAttribute("inert");
  expect(main).toHaveAttribute("inert");
  expect(within(dialog).getByRole("button", { name: "告警" })).toHaveFocus();
  expect(document.body.style.overflow).toBe("hidden");
  const first = within(dialog).getByRole("button", { name: "Open-TI" });
  const buttons = within(dialog).getAllByRole("button");
  const last = buttons.at(-1)!;
  act(() => last.focus());
  await user.keyboard("{Tab}");
  expect(first).toHaveFocus();
  await user.keyboard("{Shift>}{Tab}{/Shift}");
  expect(last).toHaveFocus();
  await user.keyboard("{Escape}");
  expect(trigger).toHaveFocus();
  expect(side).toHaveAttribute("inert");
  expect(side).toHaveAttribute("aria-hidden", "true");
  expect(main).not.toHaveAttribute("inert");
  expect(document.body.style.overflow).toBe("");
});

test("窄屏选择页面后关闭抽屉并聚焦正文，重开后还能导航", async () => {
  navigationSize(true);
  const user = userEvent.setup();
  const { container } = renderLayout();
  // A DOM-based automation must open the drawer before interacting with its controls.
  fireEvent.click(container.querySelector(".oti-nav-item[aria-label='检索']")!);
  expect(screen.getByRole("heading", { name: "alerts content" })).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "打开导航" }));
  await user.click(within(screen.getByRole("navigation")).getByRole("button", { name: "检索" }));
  expect(await screen.findByRole("heading", { name: "search content" })).toBeInTheDocument();
  expect(screen.getByRole("main")).toHaveFocus();
  expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "打开导航" }));
  expect(within(screen.getByRole("navigation")).getByRole("button", { name: "检索" })).toHaveFocus();
  await user.click(screen.getByRole("button", { name: "关闭导航" }));
  expect(screen.getByRole("button", { name: "打开导航" })).toHaveFocus();
});

test("桌面收起后的图标仍能切换页面，收起状态保持", async () => {
  navigationSize(false);
  const user = userEvent.setup();
  const { container } = renderLayout();
  await user.click(screen.getByRole("button", { name: "收起侧栏" }));
  expect(container.querySelector(".oti-shell")).toHaveClass("is-collapsed");
  await user.click(within(screen.getByRole("navigation")).getByRole("button", { name: "检索" }));
  expect(await screen.findByRole("heading", { name: "search content" })).toBeInTheDocument();
  expect(container.querySelector(".oti-shell")).toHaveClass("is-collapsed");
  expect(screen.getByRole("navigation")).toBeInTheDocument();
});

test("调整窗口宽度会解除抽屉状态，并在恢复窄屏时保持关闭", async () => {
  const resize = navigationSize(true);
  const user = userEvent.setup();
  const { container } = renderLayout();
  await user.click(screen.getByRole("button", { name: "打开导航" }));
  resize(false);
  await waitFor(() => expect(document.body.style.overflow).toBe(""));
  expect(screen.getByRole("navigation")).toBeInTheDocument();
  expect(container.querySelector("aside")).not.toHaveAttribute("inert");
  resize(true);
  expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "打开导航" })).toHaveAttribute("aria-expanded", "false");
});

test("只有用户管理权限时导航和品牌入口不会跳转到未授权业务页", async () => {
  navigationSize(false);
  const user = userEvent.setup();
  renderLayout({ ...ME_VIEWER, roles: [], permissions: ["users:write"] }, "/settings");
  const nav = screen.getByRole("navigation");
  expect(within(nav).getAllByRole("button")).toHaveLength(1);
  expect(within(nav).getByRole("button", { name: "配置" })).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Open-TI" }));
  expect(screen.getByRole("heading", { name: "settings content" })).toBeInTheDocument();
});
