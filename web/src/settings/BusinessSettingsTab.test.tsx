import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import BusinessSettingsTab from "./BusinessSettingsTab";
import { renderApp } from "../test/render";
import { server } from "../test/server";
import { CONFIG_STATUS, ME_CONFIG_ADMIN } from "../test/fixtures";

test("save nested numeric policy and edited schedule with version checking", async () => {
  let body: unknown;
  const cfg = { kind: "operations", version: 2, source: "db", digest: "x", yaml: "", data: { risk: { high_score: 65 }, schedules: { recheck_watchlist: "*/10 * * * *" } } };
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_CONFIG_ADMIN)),
    http.get("*/api/v1/config/operations", () => HttpResponse.json(cfg)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/admin/settings-schema", () => HttpResponse.json({ operations: { properties: {
      risk: { $ref: "#/$defs/Risk" }, schedules: { type: "object", additionalProperties: { type: "string" } },
    }, $defs: { Risk: { properties: { high_score: { type: "integer", minimum: 3, maximum: 99 } } } } } })),
    http.put("*/api/v1/config/operations", async ({ request }) => { body = await request.json(); return HttpResponse.json({ ...cfg, version: 3 }); }),
  );
  renderApp(<BusinessSettingsTab kind="operations" />);
  const user = userEvent.setup();
  const score = await screen.findByLabelText("高风险起始分数");
  await user.clear(score);
  await user.type(score, "70");
  await user.click(screen.getByText("后台任务时间"));
  const cron = await screen.findByLabelText("域名监视复查");
  await user.clear(cron);
  await user.type(cron, "*/20 * * * *");
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).toMatchObject({ base_version: 2, data: { risk: { high_score: 70 }, schedules: { recheck_watchlist: "*/20 * * * *" } } }));
});
