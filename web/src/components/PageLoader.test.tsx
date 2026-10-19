import { render, screen, waitFor } from "@testing-library/react";
import { lazyPage, PageSuspense } from "./PageLoader";

function Page() {
  return <p>页面内容</p>;
}

beforeEach(() => sessionStorage.clear());

test("页面分块加载成功：正常显示", async () => {
  const Lazy = lazyPage(async () => ({ default: Page }), vi.fn());
  render(<PageSuspense><Lazy /></PageSuspense>);
  expect(await screen.findByText("页面内容")).toBeInTheDocument();
});

test("分块加载失败（发布了新版本）：自动刷新一次页面", async () => {
  const reload = vi.fn();
  const Lazy = lazyPage(() => Promise.reject(new TypeError("Failed to fetch dynamically imported module")), reload);
  render(<PageSuspense><Lazy /></PageSuspense>);
  await waitFor(() => expect(reload).toHaveBeenCalledTimes(1));
  expect(screen.queryByText("页面加载失败")).toBeNull();
});

test("刷新后仍然失败：显示加载失败与刷新按钮，不再自动刷新", async () => {
  sessionStorage.setItem("oti-chunk-reload", "1");
  const reload = vi.fn();
  const Lazy = lazyPage(() => Promise.reject(new TypeError("Failed to fetch dynamically imported module")), reload);
  render(<PageSuspense reload={reload}><Lazy /></PageSuspense>);
  expect(await screen.findByText("页面加载失败")).toBeInTheDocument();
  expect(reload).not.toHaveBeenCalled();
  screen.getByRole("button", { name: "刷新页面" }).click();
  expect(reload).toHaveBeenCalledTimes(1);
});

test("加载成功后清除刷新标记，下次发布仍可自动刷新", async () => {
  sessionStorage.setItem("oti-chunk-reload", "1");
  const Lazy = lazyPage(async () => ({ default: Page }), vi.fn());
  render(<PageSuspense><Lazy /></PageSuspense>);
  await screen.findByText("页面内容");
  expect(sessionStorage.getItem("oti-chunk-reload")).toBeNull();
});
