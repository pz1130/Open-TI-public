import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import TakedownTab from "./TakedownTab";
import { CONFIG_STATUS, CONFIG_TAKEDOWN, ME_CONFIG_ADMIN } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

beforeEach(() => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_CONFIG_ADMIN)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/config/takedown", () => HttpResponse.json(CONFIG_TAKEDOWN)),
  );
});

test("save the edited SLA and platform list from the form", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(http.put("*/api/v1/config/takedown", async ({ request }) => {
    body = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json({ ...CONFIG_TAKEDOWN, version: 1 });
  }));
  const user = userEvent.setup();
  renderApp(<TakedownTab />);
  const hosting = await screen.findByLabelText("托管商 SLA（小时）");
  await user.clear(hosting);
  await user.type(hosting, "24");
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).not.toBeNull());
  expect(body).toMatchObject({ base_version: 0, data: { sla_hours: { hosting: 24 }, platforms: [{ id: "linkedin" }] } });
});

test("YAML mode saves the validated YAML text", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(
    http.post("*/api/v1/config/takedown/validate", () => HttpResponse.json({ ok: true, yaml: CONFIG_TAKEDOWN.yaml, data: CONFIG_TAKEDOWN.data, errors: [] })),
    http.put("*/api/v1/config/takedown", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json(CONFIG_TAKEDOWN);
    }),
  );
  const user = userEvent.setup();
  renderApp(<TakedownTab />);
  await user.click(await screen.findByText("YAML"));
  expect(await screen.findByLabelText("下架渠道 YAML")).toHaveValue(CONFIG_TAKEDOWN.yaml);
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).toMatchObject({ yaml: CONFIG_TAKEDOWN.yaml }));
});
