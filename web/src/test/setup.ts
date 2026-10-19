import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach } from "vitest";
import { vi } from "vitest";
import i18n from "../i18n";
import { server } from "./server";

if (!window.localStorage) {
  const values = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, String(value)),
    removeItem: (key: string) => values.delete(key),
    clear: () => values.clear(),
    key: (index: number) => [...values.keys()][index] ?? null,
    get length() { return values.size; },
  });
}

// jsdom 没有 matchMedia / ResizeObserver，Ant Design 的响应式组件需要
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false, media: query, onchange: null,
    addListener: () => {}, removeListener: () => {},
    addEventListener: () => {}, removeEventListener: () => {}, dispatchEvent: () => false,
  }),
});
class NoopResizeObserver {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
window.ResizeObserver = NoopResizeObserver as unknown as typeof ResizeObserver;
const computedStyle = window.getComputedStyle.bind(window);
window.getComputedStyle = (element) => computedStyle(element);

// 出现 act 警告说明有界面更新发生在测试的等待之外，断言可能看到的是中间状态。
// 等待界面变化请用 Testing Library 的 waitFor / findBy*，不要用 vi.waitFor。
const actWarnings: string[] = [];
const consoleError = console.error.bind(console);
let errorSpy: { mockRestore: () => void } | undefined;
beforeEach(() => {
  actWarnings.length = 0;
  errorSpy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    const text = args.map(String).join(" ");
    if (text.includes("not wrapped in act")) actWarnings.push(text.split("\n")[0]);
    consoleError(...args);
  });
});

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(async () => {
  server.resetHandlers();
  cleanup();
  window.localStorage.clear();
  await i18n.changeLanguage("zh-CN");
  errorSpy?.mockRestore();
  if (actWarnings.length) {
    throw new Error(`测试中出现 ${actWarnings.length} 条 act 警告：${actWarnings[0]}`);
  }
});
afterAll(() => server.close());
