import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import SharingTab from "./SharingTab";
import { CONFIG_SHARING, CONFIG_STATUS, ME_CONFIG_ADMIN } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("pasted CA certificate is included in the syslog test", async () => {
  let tested: Record<string, unknown> | null = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_CONFIG_ADMIN)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/config/sharing", () => HttpResponse.json(CONFIG_SHARING)),
    http.get("*/api/v1/config/sharing/secrets", () => HttpResponse.json({ encryption_key: true, secrets: [] })),
    http.post("*/api/v1/config/sharing/test", async ({ request }) => {
      tested = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ok: false, error: "TLS 握手失败（SSLCertVerificationError）" });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SharingTab />);
  await user.type(await screen.findByLabelText("CA 证书（PEM）"), "-----BEGIN CERTIFICATE-----");
  await user.click(screen.getByRole("button", { name: "发送 syslog 测试事件" }));
  expect(await screen.findByText("发送失败：TLS 握手失败（SSLCertVerificationError）")).toBeInTheDocument();
  expect(tested).toMatchObject({ target: "syslog", sharing: { siem: { syslog: { ca_pem: "-----BEGIN CERTIFICATE-----" } } } });
});

test("clearing a stored signing key is included in the webhook test", async () => {
  let tested: Record<string, unknown> | null = null;
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_CONFIG_ADMIN)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/config/sharing", () => HttpResponse.json(CONFIG_SHARING)),
    http.get("*/api/v1/config/sharing/secrets", () => HttpResponse.json({ encryption_key: true, secrets: [
      { name: "siem_signing_key", set: true, hint: "1234", source: "db", updated_by: "ops", updated_at: "2026-10-13T00:00:00Z" },
    ] })),
    http.post("*/api/v1/config/sharing/test", async ({ request }) => {
      tested = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ok: false, error: "需要签名密钥" });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SharingTab />);
  await user.click(await screen.findByRole("button", { name: "清除" }));
  await user.click(screen.getByRole("button", { name: "发送 Webhook 测试事件" }));
  expect(await screen.findByText("发送失败：需要签名密钥")).toBeInTheDocument();
  expect(tested).toMatchObject({ target: "webhook", secrets: { siem_signing_key: null } });
});
