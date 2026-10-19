import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { useState } from "react";
import { Route, Routes } from "react-router";
import SubmitLeadModal from "./SubmitLeadModal";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("提交平台链接：提示不会自动截图，提交后上传截图并跳到新告警", async () => {
  const bodies: unknown[] = [];
  const uploads: string[] = [];
  server.use(
    http.get("*/api/v1/submissions/platform", () =>
      HttpResponse.json({ url: "https://t.me/sbr_support", platform: "telegram", platform_name: "Telegram", fetch: false, error: null }),
    ),
    http.post("*/api/v1/submissions", async ({ request }) => {
      bodies.push(await request.json());
      return HttpResponse.json({ alert_id: 42, finding_id: 9, url: "https://t.me/sbr_support", platform: "telegram", created_alert: true }, { status: 201 });
    }),
    http.post("*/api/v1/alerts/42/evidence", ({ request }) => {
      uploads.push(request.headers.get("content-type") ?? "");
      return HttpResponse.json({ id: 1, kind: "upload", content_type: "image/png", sha256: "a".repeat(64), size: 3,
        captured_at: "2026-10-07T08:00:00Z", node_id: "upload", method: "analyst-upload", source_url: null,
        uploaded_by: "alice", original_sha256: "b".repeat(64) }, { status: 201 });
    }),
  );
  const user = userEvent.setup();
  renderApp(
    <Routes>
      <Route path="/" element={<SubmitLeadModal open onClose={() => {}} />} />
      <Route path="/alerts/:id" element={<div>alert page</div>} />
    </Routes>,
  );
  await user.type(screen.getByLabelText("链接"), "https://t.me/sbr_support");
  expect(await screen.findByText(/Telegram 链接：平台不会访问该页面/)).toBeInTheDocument();
  await user.click(screen.getByLabelText("冒充账号"));
  await user.type(screen.getByLabelText("说明"), "冒充客服收取手续费");
  const file = new File([new Uint8Array([137, 80, 78])], "shot.png", { type: "image/png" });
  await user.upload(screen.getByTestId("lead-files").querySelector("input[type=file]") as HTMLInputElement, file);
  await user.click(screen.getByRole("button", { name: "提交" }));
  expect(await screen.findByText("alert page")).toBeInTheDocument();
  expect(bodies).toEqual([{ url: "https://t.me/sbr_support", category: "impersonation_account", severity: "high", description: "冒充客服收取手续费" }]);
  expect(uploads).toEqual(["image/png"]);
});

test("内网地址给出错误提示且不能提交", async () => {
  server.use(
    http.get("*/api/v1/submissions/platform", () =>
      HttpResponse.json({ url: null, platform: null, platform_name: null, fetch: false, error: "private or reserved address" }),
    ),
  );
  const user = userEvent.setup();
  renderApp(<SubmitLeadModal open onClose={() => {}} />);
  await user.type(screen.getByLabelText("链接"), "http://10.0.0.1/");
  expect(await screen.findByText("内网或保留地址不能提交")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "提交" })).toBeDisabled();
});

function Harness() {
  const [open, setOpen] = useState(true);
  return (
    <>
      <button onClick={() => setOpen(true)}>reopen</button>
      <SubmitLeadModal open={open} onClose={() => setOpen(false)} />
    </>
  );
}

test("取消后清空已选截图，不会带到下一条线索", async () => {
  const user = userEvent.setup();
  renderApp(<Harness />);
  const input = (await screen.findByTestId("lead-files")).querySelector("input[type=file]") as HTMLInputElement;
  await user.upload(input, new File([new Uint8Array([137, 80, 78])], "account-a.png", { type: "image/png" }));
  expect(screen.getByText("account-a.png")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "取消" }));
  await user.click(screen.getByRole("button", { name: "reopen" }));
  await screen.findByTestId("lead-files");
  expect(screen.queryByText("account-a.png")).toBeNull();
});

test("连续输入链接只检查一次平台名单", async () => {
  const seen: string[] = [];
  server.use(
    http.get("*/api/v1/submissions/platform", ({ request }) => {
      seen.push(new URL(request.url).searchParams.get("url") ?? "");
      return HttpResponse.json({ url: "https://sbr-pay.top/x", platform: null, platform_name: null, fetch: true, error: null });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SubmitLeadModal open onClose={() => {}} />);
  await user.type(screen.getByLabelText("链接"), "https://sbr-pay.top/x");
  expect(await screen.findByText(/平台会用隔离浏览器自动截图/)).toBeInTheDocument();
  expect(seen).toEqual(["https://sbr-pay.top/x"]);
});
