import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { delay, http, HttpResponse } from "msw";
import DashboardPage from "./DashboardPage";
import { CONNECTORS, DASHBOARD, EMPTY_DASHBOARD, ME_ADMIN, ME_ANALYST, ME_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

/** react-grid-layout 用容器宽度决定网格；jsdom 里没有布局，手动给出宽度。 */
function setWidth(px: number) {
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(px);
}

beforeEach(() => setWidth(1200));
afterEach(() => vi.restoreAllMocks());

const card = (title: string) => screen.getByText(title, { selector: ".ant-card-head-title" }).closest(".opti-widget") as HTMLElement;
const OK = /确\s*定|OK/;
/** 按钮文字查找；AntD 页面里 getByRole + name 要计算整棵树的可访问名称，很慢。 */
const button = (text: string | RegExp, root: HTMLElement = document.body) =>
  within(root).getByText(text, { selector: "button span" }).closest("button") as HTMLElement;
const findButton = async (text: string | RegExp) => {
  await screen.findByText(text, { selector: "button span" });
  return button(text);
};

const SMALL_LAYOUT_DEFAULT = http.get("*/api/v1/dashboard/layout", () =>
  HttpResponse.json({
    source: "default",
    layout: { version: 1, days: 30, widgets: [{ id: "trend", type: "trend", x: 0, y: 0, w: 8, h: 5, params: { days: null, category: null } }] },
  }),
);

/** 编辑类测试用两张卡片的个人布局，避免每次点击都重新渲染全部 14 张内置卡片。 */
const SMALL_LAYOUT = http.get("*/api/v1/dashboard/layout", () =>
  HttpResponse.json({
    source: "user",
    layout: {
      version: 1, days: 30,
      widgets: [
        { id: "trend", type: "trend", x: 0, y: 0, w: 8, h: 5, params: { days: null, category: null } },
        { id: "networks", type: "networks", x: 8, y: 0, w: 4, h: 5, params: { days: null, limit: null } },
      ],
    },
  }),
);

test("没有布局时按内置默认显示，与改造前一致", async () => {
  const asked: (string | null)[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/dashboard", ({ request }) => {
      asked.push(new URL(request.url).searchParams.get("days"));
      return HttpResponse.json(DASHBOARD);
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  expect(await screen.findByText("新告警")).toBeInTheDocument();
  await waitFor(() => expect(card("下架 MTTR（中位数）").textContent).toContain("20.5"));
  const chart = screen.getByRole("img", { name: "告警趋势" });
  expect(chart.querySelectorAll("rect")).toHaveLength(4); // 两天、四段非零
  expect(screen.getByText("中位数 0.5 小时（2 个样本）")).toBeInTheDocument();
  expect(screen.getByText("达标 100%（目标 < 1 小时）")).toBeInTheDocument();
  expect(screen.getAllByText("仿冒域名").length).toBeGreaterThan(0);
  expect(screen.getByRole("link", { name: "#7" })).toHaveAttribute("href", "/alerts/7");
  expect(screen.getByText("sbr-loans.com").closest("a")).toBeNull(); // 域名只作为文本
  expect(screen.getByText("超期 6 小时")).toBeInTheDocument();
  expect(screen.getByText("NL")).toBeInTheDocument();
  expect(new Set(asked)).toEqual(new Set(["30"])); // 参数相同的卡片共用一次请求
  await user.click(screen.getByText("7 天"));
  await waitFor(() => expect(asked).toContain("7"));
});

test("显示空数据", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/dashboard", () => HttpResponse.json(EMPTY_DASHBOARD)),
  );
  renderApp(<DashboardPage />);
  expect(await screen.findByText("新告警")).toBeInTheDocument();
  await waitFor(() => expect(screen.getAllByText("暂无数据").length).toBeGreaterThan(0));
  expect(screen.getByRole("img", { name: "告警趋势" }).querySelectorAll("rect")).toHaveLength(0);
});

test("按个人布局显示，卡片参数决定请求，切换天数随个人布局保存", async () => {
  const asked: string[] = [];
  const saved: unknown[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/dashboard/layout", () =>
      HttpResponse.json({
        source: "user",
        layout: {
          version: 1, days: 30,
          widgets: [
            { id: "a", type: "top", x: 0, y: 0, w: 12, h: 5, params: { category: "phishing_site", limit: 3 } },
            { id: "b", type: "future_widget", x: 0, y: 5, w: 6, h: 4, params: {} },
          ],
        },
      }),
    ),
    http.get("*/api/v1/dashboard", ({ request }) => {
      asked.push(new URL(request.url).search);
      return HttpResponse.json(DASHBOARD);
    }),
    http.put("*/api/v1/dashboard/layout", async ({ request }) => {
      const body = await request.json();
      saved.push(body);
      return HttpResponse.json({ source: "user", layout: body });
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  expect(await screen.findByText("得分最高的未处理告警")).toBeInTheDocument();
  expect(screen.queryByText("新告警")).toBeNull();
  await waitFor(() => expect(asked).toEqual(["?days=30&category=phishing_site&limit=3"]));
  await user.click(screen.getByText("90 天"));
  await waitFor(() => expect(saved).toHaveLength(1));
  expect(saved[0]).toMatchObject({ days: 90, widgets: [{ id: "a", type: "top" }] }); // 不认识的卡片不写回
});

test("没有个人布局时切换天数只影响当前页面，不保存", async () => {
  let puts = 0;
  const asked: (string | null)[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    SMALL_LAYOUT_DEFAULT,
    http.get("*/api/v1/dashboard", ({ request }) => {
      asked.push(new URL(request.url).searchParams.get("days"));
      return HttpResponse.json(DASHBOARD);
    }),
    http.put("*/api/v1/dashboard/layout", () => {
      puts += 1;
      return HttpResponse.json({});
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  await user.click(await screen.findByText("90 天"));
  await waitFor(() => expect(asked).toContain("90"));
  expect(puts).toBe(0);
});

test("编辑：添加、设置参数、移除卡片后保存", async () => {
  const saved: { widgets: { id: string; type: string; params: Record<string, unknown> }[] }[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    SMALL_LAYOUT,
    http.get("*/api/v1/alerts", () => HttpResponse.json({ items: [], next_cursor: null })),
    http.put("*/api/v1/dashboard/layout", async ({ request }) => {
      const body = (await request.json()) as (typeof saved)[number];
      saved.push(body);
      return HttpResponse.json({ source: "user", layout: body });
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  await user.click(await findButton("编辑布局"));

  await user.click(button("添加卡片"));
  const library = (await screen.findByText("卡片库")).closest('[role="dialog"]') as HTMLElement;
  expect(within(library).queryByText("连接器健康")).not.toBeNull();
  expect(within(library).queryByText("下架进度")).not.toBeNull();
  const row = library.querySelector('[data-widget-type="my_todo"]') as HTMLElement;
  await user.click(button("添加", row));
  expect(await screen.findByText("没有指派给你的未结告警")).toBeInTheDocument();

  await user.click(screen.getByLabelText("卡片设置 我的待办"));
  const modal = (await screen.findByText("显示条数")).closest('[role="dialog"]') as HTMLElement;
  await user.type(within(modal).getByRole("spinbutton"), "5");
  await user.click(button(OK, modal));

  await user.click(screen.getByLabelText("移除卡片 托管网络（High 及以上）"));
  await user.click(button("保存"));
  await waitFor(() => expect(saved).toHaveLength(1));
  const types = saved[0].widgets.map((w) => w.type);
  expect(types).toContain("my_todo");
  expect(types).not.toContain("networks");
  expect(saved[0].widgets.find((w) => w.type === "my_todo")?.params).toEqual({ limit: 5 });
  expect(await screen.findByText("布局已保存")).toBeInTheDocument();
  expect(screen.queryByText("保存", { selector: "button span" })).toBeNull();
});

test("恢复默认删除个人布局；保存失败时留在编辑模式", async () => {
  let deleted = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    SMALL_LAYOUT,
    http.put("*/api/v1/dashboard/layout", () => HttpResponse.json({ detail: "boom" }, { status: 500 })),
    http.delete("*/api/v1/dashboard/layout", () => {
      deleted += 1;
      return new HttpResponse(null, { status: 204 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  await user.click(await findButton("编辑布局"));
  await user.click(button("保存"));
  expect(await screen.findByText("操作失败：boom")).toBeInTheDocument();
  expect(button("保存")).toBeInTheDocument();

  await user.click(button("恢复默认"));
  await user.click(await findButton(OK));
  await waitFor(() => expect(deleted).toBe(1));
  expect(await screen.findByText("已恢复默认布局")).toBeInTheDocument();
});

test("没有权限的卡片不在卡片库里", async () => {
  server.use(http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)), SMALL_LAYOUT);
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  await user.click(await findButton("编辑布局"));
  await user.click(button("添加卡片"));
  const library = (await screen.findByText("卡片库")).closest('[role="dialog"]') as HTMLElement;
  expect(within(library).getByText("告警趋势")).toBeInTheDocument();
  for (const title of ["我的待办", "下架进度", "仿冒活动", "连接器健康"]) {
    expect(within(library).queryByText(title)).toBeNull();
  }
});

test("平台管理员只看到有权限的卡片，编辑机构默认时其他卡片显示占位", async () => {
  const saved: unknown[] = [];
  let dashboardCalls = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ADMIN)),
    http.get("*/api/v1/dashboard", () => {
      dashboardCalls += 1;
      return HttpResponse.json(DASHBOARD);
    }),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
    http.get("*/api/v1/dashboard/layout", () =>
      HttpResponse.json({
        source: "default",
        layout: {
          version: 1, days: 30,
          widgets: [
            { id: "t", type: "trend", x: 0, y: 0, w: 8, h: 5, params: { days: null, category: null } },
            { id: "c", type: "connector_health", x: 8, y: 0, w: 4, h: 5, params: {} },
          ],
        },
      }),
    ),
    http.get("*/api/v1/dashboard/layout/default", () =>
      HttpResponse.json({ layout: { version: 1, days: 30, widgets: [{ id: "t", type: "trend", x: 0, y: 0, w: 8, h: 5, params: {} }] } }),
    ),
    http.put("*/api/v1/dashboard/layout/default", async ({ request }) => {
      const body = await request.json();
      saved.push(body);
      return HttpResponse.json({ layout: body });
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  expect(await screen.findByText("连接器健康")).toBeInTheDocument();
  expect(await screen.findByText("crt.sh")).toBeInTheDocument(); // failing 的连接器
  expect(screen.getByText("urlscan.io")).toBeInTheDocument(); // health unknown 也算异常
  expect(screen.queryByText("告警趋势")).toBeNull();

  await user.click(button("编辑机构默认"));
  expect(screen.getByText("正在编辑机构默认布局")).toBeInTheDocument();
  expect(within(card("告警趋势")).getByText("你没有查看这张卡片数据的权限")).toBeInTheDocument();
  await user.click(button("保存为机构默认"));
  await user.click(await findButton(OK));
  await waitFor(() => expect(saved).toHaveLength(1));
  expect(saved[0]).toMatchObject({ widgets: [{ id: "t", type: "trend" }] });
  expect(dashboardCalls).toBe(0); // 占位卡片不发数据请求
});

test("窄屏单列显示，不能编辑", async () => {
  setWidth(500);
  server.use(http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)));
  renderApp(<DashboardPage />);
  expect(await screen.findByText("新告警")).toBeInTheDocument();
  expect(document.querySelector(".react-grid-layout")).toBeNull();
  expect(screen.queryByText("编辑布局", { selector: "button span" })).toBeNull();
});

test("布局加载失败时显示内置布局且不能编辑", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/dashboard/layout", () => HttpResponse.json({ detail: "down" }, { status: 503 })),
  );
  renderApp(<DashboardPage />);
  expect(await screen.findByText("布局加载失败，暂时显示内置默认布局")).toBeInTheDocument();
  expect(screen.getByText("新告警")).toBeInTheDocument();
  expect(screen.queryByText("编辑布局", { selector: "button span" })).toBeNull();
});

test("平台管理员没有机构默认时也能看到有权限的卡片", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ADMIN)),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
  );
  renderApp(<DashboardPage />);
  expect(await screen.findByText("crt.sh")).toBeInTheDocument();
  expect(card("连接器健康")).not.toBeNull();
});

test("布局里没有卡片时给出提示", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/dashboard/layout", () => HttpResponse.json({ source: "user", layout: { version: 1, days: 30, widgets: [] } })),
  );
  renderApp(<DashboardPage />);
  expect(await screen.findByText("还没有卡片，点击「编辑布局」添加")).toBeInTheDocument();
});

test("编辑机构默认时保留它原来的天数", async () => {
  const saved: { days: number }[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ADMIN)),
    http.get("*/api/v1/connectors", () => HttpResponse.json(CONNECTORS)),
    http.get("*/api/v1/dashboard/layout", () =>
      HttpResponse.json({ source: "user", layout: { version: 1, days: 7, widgets: [{ id: "c", type: "connector_health", x: 0, y: 0, w: 6, h: 5, params: {} }] } }),
    ),
    http.get("*/api/v1/dashboard/layout/default", () =>
      HttpResponse.json({ layout: { version: 1, days: 90, widgets: [{ id: "t", type: "trend", x: 0, y: 0, w: 8, h: 5, params: { days: null, category: null } }] } }),
    ),
    http.put("*/api/v1/dashboard/layout/default", async ({ request }) => {
      const body = (await request.json()) as { days: number };
      saved.push(body);
      return HttpResponse.json({ layout: body });
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  await user.click(await findButton("编辑机构默认"));
  await user.click(button("保存为机构默认"));
  await user.click(await findButton(OK));
  await waitFor(() => expect(saved).toHaveLength(1));
  expect(saved[0].days).toBe(90);
});

const selectedRange = () => document.querySelector(".ant-segmented-item-selected")?.textContent;

test("编辑时改了天数再取消，恢复进入编辑前的天数", async () => {
  let puts = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    SMALL_LAYOUT,
    http.put("*/api/v1/dashboard/layout", () => {
      puts += 1;
      return HttpResponse.json({});
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  await user.click(await findButton("编辑布局"));
  await user.click(screen.getByText("7 天"));
  expect(selectedRange()).toBe("7 天");
  await user.click(button("取消"));
  expect(selectedRange()).toBe("30 天");
  expect(puts).toBe(0);
});

test("恢复默认后直接显示新布局，不闪回旧布局", async () => {
  let reset = false;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts", () => HttpResponse.json({ items: [], next_cursor: null })),
    http.get("*/api/v1/dashboard/layout", async () => {
      if (!reset) {
        return HttpResponse.json({
          source: "user",
          layout: { version: 1, days: 30, widgets: [{ id: "m", type: "my_todo", x: 0, y: 0, w: 6, h: 5, params: { limit: null } }] },
        });
      }
      await delay(300); // 重新取布局较慢：旧布局不能在这段时间里露出来
      return HttpResponse.json({ layout: null, source: "builtin" });
    }),
    http.delete("*/api/v1/dashboard/layout", () => {
      reset = true;
      return new HttpResponse(null, { status: 204 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<DashboardPage />);
  await user.click(await findButton("编辑布局"));
  await user.click(button("恢复默认"));
  await user.click(await findButton(OK));
  await screen.findByText("已恢复默认布局");
  expect(screen.queryByText("我的待办")).toBeNull();
  expect(screen.getByText("新告警")).toBeInTheDocument();
});

test("快速切换天数时按顺序保存，最后保存的是最后点的值", async () => {
  const bodies: number[] = [];
  let inflight = 0;
  let maxInflight = 0;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    SMALL_LAYOUT,
    http.put("*/api/v1/dashboard/layout", async ({ request }) => {
      inflight += 1;
      maxInflight = Math.max(maxInflight, inflight);
      const body = (await request.json()) as { days: number };
      bodies.push(body.days);
      await delay(150);
      inflight -= 1;
      return HttpResponse.json({ source: "user", layout: body });
    }),
  );
  renderApp(<DashboardPage />);
  await screen.findByText("托管网络（High 及以上）"); // 布局加载完才知道要随个人布局保存
  fireEvent.click(screen.getByText("7 天"));
  fireEvent.click(screen.getByText("90 天")); // 第一次保存还没返回就点第二次
  await waitFor(() => expect(bodies).toEqual([7, 90]));
  await waitFor(() => expect(inflight).toBe(0));
  expect(maxInflight).toBe(1);
  expect(selectedRange()).toBe("90 天");
});

test("后台刷新布局失败时继续显示已有布局，不提示加载失败", async () => {
  server.use(http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)), SMALL_LAYOUT);
  const { client } = renderApp(<DashboardPage />);
  expect(await screen.findByText("托管网络（High 及以上）")).toBeInTheDocument();
  server.use(http.get("*/api/v1/dashboard/layout", () => HttpResponse.json({ detail: "down" }, { status: 503 })));
  await client.refetchQueries({ queryKey: ["dashboard-layout"] });
  await waitFor(() => expect(client.getQueryState(["dashboard-layout"])?.status).toBe("error"));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50)); // 等页面按 error 状态重新渲染
  });
  expect(screen.queryByText("布局加载失败，暂时显示内置默认布局")).toBeNull();
  expect(screen.getByText("托管网络（High 及以上）")).toBeInTheDocument();
  expect(screen.queryByText("编辑布局", { selector: "button span" })).not.toBeNull();
});

test("布局加载完成前不能切换天数", async () => {
  let release!: () => void;
  const loaded = new Promise<void>((r) => (release = r));
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/dashboard/layout", async () => {
      await loaded;
      return HttpResponse.json({ source: "user", layout: { version: 1, days: 30, widgets: [{ id: "t", type: "trend", x: 0, y: 0, w: 8, h: 5, params: { days: null, category: null } }] } });
    }),
  );
  renderApp(<DashboardPage />);
  const picker = (await screen.findByText("7 天")).closest(".ant-segmented") as HTMLElement;
  expect(picker).toHaveClass("ant-segmented-disabled");
  release();
  await screen.findByText("告警趋势");
  expect(picker).not.toHaveClass("ant-segmented-disabled");
});
