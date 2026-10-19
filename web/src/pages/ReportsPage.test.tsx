import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import ReportsPage from "./ReportsPage";
import { ME_VIEWER, REPORT_DETAIL } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("列出报告并按类型筛选", async () => {
  const kinds: (string | null)[] = [];
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_VIEWER)),
    http.get("*/api/v1/reports", ({ request }) => {
      kinds.push(new URL(request.url).searchParams.get("kind"));
      const { content: _c, ...summary } = REPORT_DETAIL;
      return HttpResponse.json({ items: [summary], next_cursor: null });
    }),
  );
  const user = userEvent.setup();
  renderApp(<ReportsPage />);
  expect(await screen.findByRole("link", { name: "威胁情报日报 2026-10-03" })).toHaveAttribute("href", "/reports/3");
  expect(screen.getByText("已推送")).toBeInTheDocument();
  await user.click(screen.getByText("周报"));
  await waitFor(() => expect(kinds).toContain("weekly"));
  await user.click(screen.getByText("月报"));
  await waitFor(() => expect(kinds).toContain("monthly"));
});
