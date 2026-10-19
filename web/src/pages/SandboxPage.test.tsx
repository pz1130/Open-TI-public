import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import SandboxPage from "./SandboxPage";
import { renderApp } from "../test/render";
import { server } from "../test/server";

test("测试域名与文本并高亮命中", async () => {
  let body: unknown = null;
  server.use(
    http.post("*/api/v1/rules/test", async ({ request }) => {
      body = await request.json();
      return HttpResponse.json({
        source: "current", project: "sample-brand-protection",
        domains: [
          { input: "sbr-loans.com", status: "match", domain: "sbr-loans.com", registered: "sbr-loans.com",
            reasons: [{ reason: "brand_label" }], score: { value: 48, severity: "medium", category: "typosquat_domain", breakdown: {} } },
          { input: "sbrbank.com", status: "known_lookalike", domain: "sbrbank.com", registered: "sbrbank.com", reasons: [], score: null },
        ],
        text_hits: [{ set_name: "brand", term: "Sample Brand", mode: "phrase", role: "match", context: "the sample brand offers" }],
      });
    }),
  );
  const user = userEvent.setup();
  const { container } = renderApp(<SandboxPage />);
  await user.type(screen.getByLabelText("域名（每行一个）"), "sbr-loans.com{Enter}sbrbank.com");
  await user.type(screen.getByLabelText("文本"), "The Sample Brand offers");
  await user.click(screen.getByRole("button", { name: "测试" }));
  expect(await screen.findByText("已知合法相似方")).toBeInTheDocument();
  expect(screen.getByText("命中")).toBeInTheDocument();
  expect(container.querySelector("mark")?.textContent).toBe("sample brand");
  expect(body).toEqual({ domains: ["sbr-loans.com", "sbrbank.com"], text: "The Sample Brand offers", draft_yaml: null });
});

test("草稿有误时显示原因", async () => {
  server.use(
    http.post("*/api/v1/rules/test", () =>
      HttpResponse.json({ detail: { message: "草稿 校验失败：authorization_ref 必填" } }, { status: 422 }),
    ),
  );
  const user = userEvent.setup();
  renderApp(<SandboxPage />);
  await user.type(screen.getByLabelText("草稿规则（可选）"), "project: x");
  await user.click(screen.getByRole("button", { name: "测试" }));
  expect(await screen.findByText(/authorization_ref 必填/)).toBeInTheDocument();
});
