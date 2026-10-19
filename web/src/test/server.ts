import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { EMPTY_DASHBOARD } from "./fixtures";

export const server = setupServer(
  http.get("*/api/v1/projects/current", () => HttpResponse.json({ project_id: "sbr", rules_version: 0 })),
  http.get("*/api/v1/auth/providers", () => HttpResponse.json({ local: true, oidc: false, oidc_label: "" })),
  http.get("*/api/v1/dashboard", () => HttpResponse.json(EMPTY_DASHBOARD)),
  http.get("*/api/v1/dashboard/layout", () => HttpResponse.json({ layout: null, source: "builtin" })),
  http.get("*/api/v1/dashboard/layout/default", () => HttpResponse.json({ layout: null })),
);
