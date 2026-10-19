import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import MasterKeyTab from "./MasterKeyTab";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("initialize key, invalidate credentials and keep backup out of query cache", async () => {
  let configured = false;
  const backup = "test-only-master-key-for-backup";
  server.use(
    http.get("*/api/v1/admin/master-key", () => HttpResponse.json({ configured, source: configured ? "managed" : "none", has_encrypted_credentials: false })),
    http.post("*/api/v1/admin/master-key", async ({ request }) => {
      expect(await request.json()).toEqual({});
      configured = true;
      return HttpResponse.json({ configured: true, backup_key: backup });
    }),
  );
  const { client } = renderApp(<MasterKeyTab />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "生成并保存主密钥" }));
  expect(await screen.findByText(backup)).toBeInTheDocument();
  await waitFor(() => expect(screen.queryByRole("button", { name: "生成并保存主密钥" })).toBeNull());
  expect(JSON.stringify(client.getQueryCache().getAll().map((q) => q.state.data))).not.toContain(backup);
  expect(client.getMutationCache().getAll()).toHaveLength(0);
  await user.click(screen.getByRole("button", { name: "已备份，隐藏密钥" }));
  expect(screen.queryByText(backup)).toBeNull();
});

test("existing encrypted credentials require import and do not offer generation", async () => {
  let body: unknown;
  server.use(
    http.get("*/api/v1/admin/master-key", () => HttpResponse.json({ configured: false, source: "none", has_encrypted_credentials: true })),
    http.post("*/api/v1/admin/master-key", async ({ request }) => {
      body = await request.json();
      return HttpResponse.json({ detail: "该主密钥无法解密已有凭据，请导入原主密钥" }, { status: 422 });
    }),
  );
  renderApp(<MasterKeyTab />);
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText("导入原主密钥"), "restore-original-key");
  expect(screen.queryByRole("button", { name: "生成并保存主密钥" })).toBeNull();
  await user.click(screen.getByRole("button", { name: "导入并验证" }));
  expect(await screen.findByText("该主密钥无法解密已有凭据，请导入原主密钥")).toBeInTheDocument();
  expect(body).toEqual({ key: "restore-original-key" });
});
