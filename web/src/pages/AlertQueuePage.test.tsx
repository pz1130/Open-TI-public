import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { Route, Routes } from "react-router";
import AlertQueuePage from "./AlertQueuePage";
import { ALERT_SUMMARY, ME_ANALYST, ME_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("列出告警、翻页替换结果、按域名搜索重置页码", async () => {
  const seen: URLSearchParams[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/alerts", ({ request }) => {
      const params = new URL(request.url).searchParams;
      seen.push(params);
      if (params.get("page") === "2") {
        return HttpResponse.json({ items: [{ ...ALERT_SUMMARY, id: 5, domain: "sbr-grant.top", severity: "critical" }], next_cursor: null, total: 21 });
      }
      return HttpResponse.json({ items: [ALERT_SUMMARY], next_cursor: 7, total: 21 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<AlertQueuePage />);
  const row = (await screen.findByText("sbr-loans.com")).closest("tr") as HTMLElement;
  expect(within(row).getByText("高")).toBeInTheDocument();
  expect(within(row).getByText("品牌词标签")).toBeInTheDocument();
  expect(within(row).getByRole("link", { name: "T1583.001 Domains · 资源开发" })).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1583/001/");
  expect(screen.getByText("sbr-loans.com").closest("a")).toBeNull(); // 可疑域名不是链接
  expect(seen[0].getAll("status")).toEqual(["open", "acknowledged"]);
  expect(screen.queryByRole("button", { name: "加载更多" })).toBeNull();
  expect(seen[0].get("limit")).toBe("20");
  await user.click(screen.getByTitle("2"));
  expect(await screen.findByText("sbr-grant.top")).toBeInTheDocument();
  expect(screen.queryByText("sbr-loans.com")).toBeNull();
  await user.type(screen.getByPlaceholderText("搜索域名"), "grant{Enter}");
  await waitFor(() => expect(seen.at(-1)?.get("q")).toBe("grant"));
  expect(seen.at(-1)?.get("page")).toBe("1");
});

test("每行末尾有研判按钮，点击进入详情", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/alerts", () => HttpResponse.json({ items: [ALERT_SUMMARY], next_cursor: null })),
  );
  const user = userEvent.setup();
  renderApp(
    <Routes>
      <Route path="/" element={<AlertQueuePage />} />
      <Route path="alerts/:id" element={<p>detail {ALERT_SUMMARY.id}</p>} />
    </Routes>,
  );
  const row = (await screen.findByText("sbr-loans.com")).closest("tr") as HTMLElement;
  await user.click(within(row).getByRole("button", { name: "研判" }));
  expect(await screen.findByText(`detail ${ALERT_SUMMARY.id}`)).toBeInTheDocument();
});

test("接口失败时显示错误", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/alerts", () => HttpResponse.json({ detail: "service unavailable" }, { status: 503 })),
  );
  renderApp(<AlertQueuePage />);
  expect(await screen.findByRole("alert")).toHaveTextContent("service unavailable");
});

test("有研判权限才显示提交线索", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts", () => HttpResponse.json({ items: [], next_cursor: null })),
  );
  renderApp(<AlertQueuePage />);
  expect(await screen.findByRole("button", { name: "提交线索" })).toBeInTheDocument();
});

test("只读用户看不到提交线索", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/alerts", () => HttpResponse.json({ items: [], next_cursor: null })),
  );
  const { client } = renderApp(<AlertQueuePage />);
  await waitFor(() => expect(client.getQueryState(["me"])?.status).toBe("success"));
  await screen.findByRole("table");
  expect(screen.queryByRole("button", { name: "提交线索" })).toBeNull();
});


test("选择每页条数会更新请求并回到第一页", async () => {
  const seen: URLSearchParams[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/alerts", ({ request }) => {
      seen.push(new URL(request.url).searchParams);
      return HttpResponse.json({ items: [ALERT_SUMMARY], total: 120, next_cursor: null });
    }),
  );
  const user = userEvent.setup();
  renderApp(<AlertQueuePage />);
  await screen.findByText("sbr-loans.com");
  await user.click(screen.getByTitle("2"));
  await waitFor(() => expect(seen.at(-1)?.get("page")).toBe("2"));
  await user.click(screen.getByRole("combobox", { name: "每页显示条数" }));
  await user.click(await screen.findByText("50 条/页"));
  await waitFor(() => expect(seen.at(-1)?.get("limit")).toBe("50"));
  expect(seen.at(-1)?.get("page")).toBe("1");
});


test("快速忽略、查看标签和取消忽略，不跳转详情", async () => {
  let ignored = false;
  const bodies: unknown[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.get("*/api/v1/alerts", ({ request }) => {
      const mode = new URL(request.url).searchParams.get("ignored");
      const visible = mode === "only" ? ignored : !ignored;
      return HttpResponse.json({ items: visible ? [{ ...ALERT_SUMMARY, ignored }] : [], total: visible ? 1 : 0, next_cursor: null });
    }),
    http.patch("*/api/v1/alerts/7", async ({ request }) => {
      const body = await request.json() as { ignored: boolean };
      bodies.push(body);
      ignored = body.ignored;
      return HttpResponse.json({ ...ALERT_SUMMARY, ignored });
    }),
  );
  const user = userEvent.setup();
  renderApp(<AlertQueuePage />);
  await user.click(await screen.findByRole("button", { name: "忽略" }));
  await waitFor(() => expect(screen.queryByText(ALERT_SUMMARY.domain)).toBeNull());
  expect(bodies).toEqual([{ ignored: true }]);
  await user.click(screen.getByRole("combobox", { name: "忽略状态" }));
  await user.click(await screen.findByText("仅已忽略"));
  expect(await screen.findByText("已忽略")).toBeInTheDocument();
  expect(await screen.findByText(ALERT_SUMMARY.domain)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "取消忽略" }));
  await waitFor(() => expect(screen.queryByText(ALERT_SUMMARY.domain)).toBeNull());
  expect(bodies).toEqual([{ ignored: true }, { ignored: false }]);
});
