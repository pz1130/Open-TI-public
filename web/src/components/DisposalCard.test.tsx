import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import DisposalCard from "./DisposalCard";
import { ALERT_DETAIL, ME_ANALYST, TAKEDOWN, TARGET } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("推送工单与新建下架投诉", async () => {
  let pushed = false;
  let created: unknown = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_ANALYST)),
    http.post("*/api/v1/alerts/7/ticket", () => {
      pushed = true;
      return HttpResponse.json({ ref: "INC001", status: null, pushed_at: "2026-10-03T00:00:00Z", synced_at: null, available: true });
    }),
    http.get("*/api/v1/alerts/7/takedown-targets", () =>
      HttpResponse.json({ host: "sbr-loans.com", missing_hosting: ["104.16.2.2"], targets: [TARGET] }),
    ),
    http.post("*/api/v1/alerts/7/takedowns", async ({ request }) => {
      created = await request.json();
      return HttpResponse.json(TAKEDOWN, { status: 201 });
    }),
  );
  const user = userEvent.setup();
  const detail = { ...ALERT_DETAIL, ticket: { ref: null, status: null, pushed_at: null, synced_at: null, available: true } };
  renderApp(<DisposalCard detail={detail} />);

  await user.click(await screen.findByRole("button", { name: "推送工单" }));
  await waitFor(() => expect(pushed).toBe(true));

  await user.click(screen.getByRole("button", { name: "新建下架投诉" }));
  expect(await screen.findByText(/104\.16\.2\.2/)).toBeInTheDocument();
  await user.click(screen.getByRole("radio", { name: /Cheap Registrar LLC/ }));
  await user.click(screen.getByText("English"));
  await user.click(screen.getByRole("button", { name: "生成草稿" }));
  await waitFor(() => expect(created).toEqual({ target_id: "registrar:cheap", language: "en-US" }));
});

test("没有权限时不显示操作", async () => {
  server.use(http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_ANALYST, permissions: ["alerts:read", "takedown:read"] })));
  renderApp(<DisposalCard detail={{ ...ALERT_DETAIL, takedowns: [{ id: 5, state: "submitted", target_name: "Cheap Registrar LLC", target_kind: "registrar", updated_at: "2026-10-03T00:00:00Z" }] }} />);
  expect(await screen.findByRole("link", { name: "#5" })).toHaveAttribute("href", "/takedowns?id=5");
  expect(screen.queryByRole("button", { name: "新建下架投诉" })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "下载证据包" })).not.toBeInTheDocument();
});

test("Jira / ServiceNow 工单编号可点击跳转", async () => {
  server.use(http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_ANALYST, permissions: ["alerts:read"] })));
  const ticket = { ref: "SEC-12", status: null, pushed_at: "2026-10-03T00:00:00Z", synced_at: null, available: true,
    url: "https://acme.atlassian.net/browse/SEC-12" };
  renderApp(<DisposalCard detail={{ ...ALERT_DETAIL, ticket }} />);
  const link = await screen.findByRole("link", { name: "SEC-12" });
  expect(link).toHaveAttribute("href", "https://acme.atlassian.net/browse/SEC-12");
  expect(link).toHaveAttribute("target", "_blank");
  expect(link).toHaveAttribute("rel", "noreferrer");
});
