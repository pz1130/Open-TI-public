import { screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { ALERT_SUMMARY, CONNECTORS } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { server } from "../../test/server";
import { CATALOG, type Widget } from "../catalog";
import { WIDGETS } from ".";
import { CampaignsWidget, ConnectorHealthWidget, MyTodoWidget, TakedownsWidget } from "./operations";

const widget = (type: string, params: Widget["params"] = {}): Widget => ({ id: "x", type, x: 0, y: 0, w: 6, h: 5, params });

test("卡片库里的每种类型都有渲染组件", () => {
  expect(Object.keys(WIDGETS).sort()).toEqual(CATALOG.map((d) => d.type).sort());
});

test("我的待办：按服务器给出的紧急程度顺序显示，条数交给服务器", async () => {
  const asked: string[] = [];
  const alert = (id: number, severity: string) => ({ ...ALERT_SUMMARY, id, severity, domain: `d${id}.top` });
  server.use(
    http.get("*/api/v1/alerts", ({ request }) => {
      asked.push(new URL(request.url).search);
      return HttpResponse.json({ items: [alert(3, "critical"), alert(2, "critical")], next_cursor: null });
    }),
  );
  renderApp(<MyTodoWidget widget={widget("my_todo", { limit: 2 })} days={30} />);
  await screen.findByText("#3");
  expect(screen.getAllByRole("link").map((a) => a.textContent)).toEqual(["#3", "#2"]);
  expect(asked).toEqual(["?assigned_to_me=true&order=urgency&limit=2"]);
});

test("下架进度：只列出数量不为零的状态和投诉最多的对象", async () => {
  server.use(
    http.get("*/api/v1/takedowns/stats", () =>
      HttpResponse.json({
        by_state: { submitted: 2, removed: 5, draft: 0 },
        mttr_hours: 30.5,
        targets: [
          { name: "Example Registrar", kind: "registrar", total: 4, removed: 3, rejected: 0, median_response_hours: 10 },
          { name: "Big Host", kind: "hosting", total: 6, removed: 2, rejected: 1, median_response_hours: null },
        ],
      }),
    ),
  );
  renderApp(<TakedownsWidget widget={widget("takedowns")} days={30} />);
  const mttr = await screen.findByText("MTTR（发现到下架）");
  expect(mttr.closest(".ant-statistic")?.textContent).toContain("30.5"); // 整数与小数分开渲染
  expect(screen.getByText("已提交")).toBeInTheDocument();
  expect(screen.queryByText("草稿")).toBeNull();
  const rows = [...document.querySelectorAll("tbody tr")].map((r) => r.textContent);
  expect(rows[0]).toContain("Big Host");
});

test("仿冒活动：候选数量与最近确认的活动", async () => {
  server.use(
    http.get("*/api/v1/campaigns", ({ request }) => {
      const state = new URL(request.url).searchParams.get("state");
      const base = { state, name: null, label_value: "sbr-a.top", member_count: 3, pending_count: 0, active_alerts: 2, top_severity: "high", signal_kinds: ["ip"], updated_at: "2026-10-08T08:00:00Z" };
      return state === "candidate"
        ? HttpResponse.json({ items: [{ ...base, id: 1 }], total: 4 })
        : HttpResponse.json({ items: [{ ...base, id: 6, name: "贷款诈骗团伙" }, { ...base, id: 7, name: "第二个" }], total: 2 });
    }),
  );
  renderApp(<CampaignsWidget widget={widget("campaigns", { limit: 1 })} days={30} />);
  expect(await screen.findByText("4")).toBeInTheDocument();
  expect(await screen.findByRole("link", { name: "贷款诈骗团伙" })).toHaveAttribute("href", "/campaigns/6");
  expect(screen.queryByText("第二个")).toBeNull();
});

test("连接器健康：只列出已启用且异常的连接器", async () => {
  const healthy = { ...CONNECTORS[0], id: "ok1", name: "Healthy One", health: "ok", errors_24h: 0 };
  const disabled = { ...CONNECTORS[0], id: "off", name: "Switched Off", enabled: false, health: "disabled" };
  server.use(http.get("*/api/v1/connectors", () => HttpResponse.json([...CONNECTORS, healthy, disabled])));
  renderApp(<ConnectorHealthWidget widget={widget("connector_health")} days={30} />);
  expect(await screen.findByText("crt.sh")).toBeInTheDocument();
  expect(screen.getByText("24 小时内出错 1 次")).toBeInTheDocument();
  expect(screen.getByText("最近成功：从未成功")).toBeInTheDocument(); // urlscan 从未成功
  expect(screen.queryByText("Healthy One")).toBeNull();
  expect(screen.queryByText("Switched Off")).toBeNull();
});

test("连接器全部正常时给出提示", async () => {
  server.use(http.get("*/api/v1/connectors", () => HttpResponse.json([{ ...CONNECTORS[0], health: "ok", errors_24h: 0 }])));
  renderApp(<ConnectorHealthWidget widget={widget("connector_health")} days={30} />);
  expect(await screen.findByText("已启用的 1 个连接器全部正常")).toBeInTheDocument();
});
