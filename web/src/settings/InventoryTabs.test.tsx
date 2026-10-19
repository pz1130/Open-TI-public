import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import SoftwareTab from "./SoftwareTab";
import VendorsTab from "./VendorsTab";
import { CONFIG_SOFTWARE, CONFIG_STATUS, CONFIG_VENDORS, ME_CONFIG_ADMIN } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

beforeEach(() => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_CONFIG_ADMIN)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/config/vendors", () => HttpResponse.json(CONFIG_VENDORS)),
    http.get("*/api/v1/config/software", () => HttpResponse.json(CONFIG_SOFTWARE)),
    http.get("*/api/v1/config/vendors/rematch", () => HttpResponse.json({ status: "done", version: 1, alerts: 2, error: null, at: "2026-10-12T08:00:00Z" })),
    http.get("*/api/v1/config/software/rematch", () => HttpResponse.json({ status: "queued", version: 1, alerts: null, error: null, at: "2026-10-12T08:00:00Z" })),
  );
});

test("vendor inventory shows rematch result and saves a new row", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(http.put("*/api/v1/config/vendors", async ({ request }) => {
    body = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({ ...CONFIG_VENDORS, version: 2 });
  }));
  const user = userEvent.setup();
  renderApp(<VendorsTab />);
  expect(await screen.findByText("v1 重新比对完成，新增 2 条告警")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "添加一行" }));
  const ids = screen.getAllByLabelText("ID");
  await user.type(ids[ids.length - 1], "acme");
  const names = screen.getAllByLabelText("名称");
  await user.type(names[names.length - 1], "Acme Cloud");
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).toMatchObject({
    data: { vendors: [{ id: "example-cloud" }, { id: "acme", name: "Acme Cloud" }] },
  }));
});

test("software inventory suggests KEV products for its vendor", async () => {
  server.use(http.get("*/api/v1/config/software/kev-products", ({ request }) => HttpResponse.json(
    new URL(request.url).searchParams.get("vendor") === "Fortinet" ? ["FortiOS", "FortiProxy"] : [],
  )));
  const user = userEvent.setup();
  renderApp(<SoftwareTab />);
  expect(await screen.findByText("v1 已排队，等待重新比对")).toBeInTheDocument();
  await user.click(screen.getAllByLabelText("产品")[0]);
  expect(await screen.findByRole("option", { name: "FortiProxy" })).toBeInTheDocument();
});
