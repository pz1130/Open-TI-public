import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import TemplatesTab from "./TemplatesTab";
import { CONFIG_STATUS, CONFIG_TEMPLATES, ME_CONFIG_ADMIN } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

beforeEach(() => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(ME_CONFIG_ADMIN)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/config/takedown_templates", () => HttpResponse.json(CONFIG_TEMPLATES)),
    http.post("*/api/v1/config/takedown_templates/preview", async ({ request }) => {
      const value = (await request.json()) as { text: string };
      return HttpResponse.json(value.text.includes("$nope")
        ? { subject: "", body: "", errors: ["未知的占位符：$nope"] }
        : { subject: "预览主题", body: "预览正文\n", errors: [] });
    }),
  );
});

test("insert a placeholder and show preview errors", async () => {
  const user = userEvent.setup();
  renderApp(<TemplatesTab />);
  const editor = await screen.findByLabelText("模板内容");
  expect(await screen.findByText("预览主题")).toBeInTheDocument();
  await user.click(editor);
  await user.click(screen.getByRole("button", { name: "$domain" }));
  expect((editor as HTMLTextAreaElement).value).toContain("$domain");
  await user.type(editor, " $nope");
  expect(await screen.findByText("未知的占位符：$nope")).toBeInTheDocument();
});

test("restore the built-in template and save the full set", async () => {
  let body: Record<string, unknown> | null = null;
  server.use(http.put("*/api/v1/config/takedown_templates", async ({ request }) => {
    body = (await request.json()) as Record<string, unknown>;
    return HttpResponse.json(CONFIG_TEMPLATES);
  }));
  const user = userEvent.setup();
  renderApp(<TemplatesTab />);
  const editor = await screen.findByLabelText("模板内容");
  await user.clear(editor);
  await user.type(editor, "Subject: 改过");
  await user.click(screen.getByRole("button", { name: "恢复内置模板" }));
  expect(editor).toHaveValue("Subject: 内置\n正文");
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).toMatchObject({ data: { "zh-CN": { registrar: "Subject: 内置\n正文" } } }));
});
