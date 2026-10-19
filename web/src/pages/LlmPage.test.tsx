import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import LlmPage from "./LlmPage";
import { LLM_PRESETS, LLM_PROVIDER, LLM_SETTINGS, LLM_STATUS, ME_AUDITOR, ME_LLM_ADMIN } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

function mock({ me = ME_LLM_ADMIN, providers = [LLM_PROVIDER], settings = LLM_SETTINGS, status = LLM_STATUS } = {}) {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(me)),
    http.get("*/api/v1/llm/presets", () => HttpResponse.json(LLM_PRESETS)),
    http.get("*/api/v1/llm/providers", () => HttpResponse.json(providers)),
    http.get("*/api/v1/llm/settings", () => HttpResponse.json(settings)),
    http.get("*/api/v1/llm/status", () => HttpResponse.json(status)),
  );
}

async function pick(user: ReturnType<typeof userEvent.setup>, label: string, option: string) {
  await user.click(screen.getByLabelText(label));
  await user.click(await screen.findByTitle(option));
}

test("新增供应商：选预设带出地址与模型，密钥随请求提交", async () => {
  mock({ providers: [] });
  let created: Record<string, unknown> | null = null;
  server.use(
    http.post("*/api/v1/llm/providers", async ({ request }) => {
      created = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...LLM_PROVIDER, id: 2 }, { status: 201 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<LlmPage />);
  await user.click(await screen.findByText("添加供应商"));
  await pick(user, "预设", "DeepSeek");
  expect(screen.getByLabelText("接口地址")).toHaveValue("https://api.deepseek.com/v1");
  expect(screen.getAllByLabelText("模型").at(-1)).toHaveValue("deepseek-flash");
  await user.type(screen.getByLabelText("API 密钥"), "sk-test-1234");
  await user.click(screen.getByText("保存供应商"));
  await waitFor(() => expect(created).not.toBeNull());
  expect(created).toMatchObject({
    name: "DeepSeek", preset: "deepseek", base_url: "https://api.deepseek.com/v1", model: "deepseek-flash",
    api_key: "sk-test-1234", json_mode: true, temperature: 0,
  });
  expect(created).not.toHaveProperty("proxy");
});

test("编辑：密钥留空不修改，点清除密钥发送 null", async () => {
  mock();
  const bodies: Record<string, unknown>[] = [];
  server.use(
    http.patch("*/api/v1/llm/providers/1", async ({ request }) => {
      bodies.push((await request.json()) as Record<string, unknown>);
      return HttpResponse.json(LLM_PROVIDER);
    }),
  );
  const user = userEvent.setup();
  renderApp(<LlmPage />);
  await user.click(await screen.findByLabelText("编辑 DeepSeek"));
  expect(screen.getByLabelText("API 密钥")).toHaveAttribute("placeholder", "已设置 ····abcd，留空则不修改");
  await user.click(screen.getByText("保存供应商"));
  await waitFor(() => expect(bodies).toHaveLength(1));
  expect(bodies[0]).not.toHaveProperty("api_key");
  await user.click(await screen.findByLabelText("编辑 DeepSeek"));
  await user.click(screen.getByText("清除密钥"));
  await user.click(screen.getByText("保存供应商"));
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[1]).toMatchObject({ api_key: null });
});

test("MiniMax 使用 Anthropic 地址和参数，编辑保留密钥并手填模型", async () => {
  const minimax = {
    ...LLM_PROVIDER, name: "MiniMax", preset: "minimax", base_url: "https://api.minimax.cn/anthropic/v1",
    model: "MiniMax-M2.7", json_mode: false, temperature: 0,
  };
  mock({ providers: [minimax] });
  const bodies: Record<string, unknown>[] = [];
  server.use(
    http.post("*/api/v1/llm/providers", async ({ request }) => {
      bodies.push((await request.json()) as Record<string, unknown>);
      return HttpResponse.json(minimax, { status: 201 });
    }),
    http.patch("*/api/v1/llm/providers/1", async ({ request }) => {
      bodies.push((await request.json()) as Record<string, unknown>);
      return HttpResponse.json(minimax);
    }),
  );
  const user = userEvent.setup();
  renderApp(<LlmPage />);
  await user.click(await screen.findByText("添加供应商"));
  await pick(user, "预设", "MiniMax");
  expect(screen.getByLabelText("接口地址")).toHaveValue("https://api.minimax.cn/anthropic/v1");
  expect(screen.getAllByLabelText("模型").at(-1)).toHaveValue("MiniMax-M2");
  expect(screen.getByLabelText("温度")).toHaveValue("1.0");
  expect(screen.getByText(/请选择与 Key 对应的站点/)).toBeInTheDocument();
  expect(screen.getByLabelText("请求 JSON 格式输出")).not.toBeVisible();
  await user.type(screen.getByLabelText("API 密钥"), "sk-test-minimax");
  await user.click(screen.getByText("保存供应商"));
  await waitFor(() => expect(bodies).toHaveLength(1));
  expect(bodies[0]).toMatchObject({
    preset: "minimax", base_url: "https://api.minimax.cn/anthropic/v1", temperature: 1, json_mode: false,
  });
  await user.click(await screen.findByLabelText("编辑 MiniMax"));
  expect(screen.queryByText("获取模型列表")).toBeNull();
  expect(screen.getAllByLabelText("模型").at(-1)).toHaveValue("MiniMax-M2.7");
  expect(screen.getByLabelText("温度")).toHaveValue("0.0");
  await user.click(screen.getByText("保存供应商"));
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[1]).toMatchObject({ model: "MiniMax-M2.7", temperature: 0 });
  expect(bodies[1]).not.toHaveProperty("api_key");
});

test("获取模型列表与测试连接", async () => {
  mock();
  server.use(
    http.post("*/api/v1/llm/providers/1/models", () => HttpResponse.json({ models: ["deepseek-flash", "deepseek-reasoner"] })),
    http.post("*/api/v1/llm/providers/1/test", () =>
      HttpResponse.json({ ok: true, provider: "DeepSeek", model: "deepseek-flash", verdict: "yes", confidence: 0.9, latency_ms: 120, error: null }),
    ),
  );
  const user = userEvent.setup();
  renderApp(<LlmPage />);
  await user.click(await screen.findByLabelText("测试 DeepSeek"));
  expect(await screen.findByText(/连接成功/)).toBeInTheDocument();
  await user.click(screen.getByLabelText("编辑 DeepSeek"));
  await user.click(screen.getByText("获取模型列表"));
  expect(await screen.findByText("已获取 2 个模型")).toBeInTheDocument();
});

test("只读：审计员看不到操作，表单禁用", async () => {
  mock({ me: ME_AUDITOR });
  renderApp(<LlmPage />);
  expect((await screen.findAllByText("DeepSeek")).length).toBeGreaterThan(0); // 名称列与预设列
  expect(screen.queryByText("添加供应商")).toBeNull();
  expect(screen.queryByLabelText("编辑 DeepSeek")).toBeNull();
  for (const toggle of screen.getAllByRole("switch")) expect(toggle).toBeDisabled();
});

test("警告：主密钥未配置、境外主用、运行问题", async () => {
  const intl = { ...LLM_PROVIDER, id: 3, name: "OpenAI", preset: "openai", group: "international", in_use: "primary" as const };
  mock({
    providers: [intl],
    settings: { ...LLM_SETTINGS, enabled: true, primary_id: 3 },
    status: { ...LLM_STATUS, encryption_key: false, problem: "主用供应商不可用：OpenAI 缺少 API 密钥" },
  });
  renderApp(<LlmPage />);
  expect(await screen.findByText(/尚未配置有效的主密钥/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "前往管理员主密钥设置" })).toHaveAttribute("href", "/settings/master_key");
  expect(await screen.findByText(/发送到境外第三方/)).toBeInTheDocument();
  expect(screen.getByText(/OpenAI 缺少 API 密钥/)).toBeInTheDocument();
  const table = screen.getByRole("table");
  expect(within(table).getByText("主用")).toBeInTheDocument();
});

test("启用研判前必须选主用：页面直接提示，不发请求", async () => {
  mock();
  let saved = false;
  server.use(
    http.put("*/api/v1/llm/settings", () => {
      saved = true;
      return HttpResponse.json(LLM_SETTINGS);
    }),
  );
  const user = userEvent.setup();
  renderApp(<LlmPage />);
  const toggle = await screen.findByRole("switch", { name: "启用研判" });
  await waitFor(() => expect(toggle).not.toBeDisabled());
  await user.click(toggle);
  await user.click(screen.getByText("保存"));
  expect(await screen.findByText("启用研判需要先选择主用供应商")).toBeInTheDocument();
  expect(saved).toBe(false);
});

test("后台研判任务报告的问题也显示出来（与 API 相同的只显示一次）", async () => {
  const problem = "主用供应商不可用：尚未初始化凭据加密主密钥，请由管理员前往「配置 → 管理员 → 凭据加密主密钥」完成初始化";
  mock({ status: { ...LLM_STATUS, worker_problem: problem, worker_checked_at: "2026-10-10T08:00:00Z" } });
  const { unmount } = renderApp(<LlmPage />);
  expect(await screen.findByText(`后台研判任务报告：${problem}`)).toBeInTheDocument();
  unmount();
  mock({ status: { ...LLM_STATUS, problem, worker_problem: problem, worker_checked_at: "2026-10-10T08:00:00Z" } });
  renderApp(<LlmPage />);
  expect(await screen.findByText(problem)).toBeInTheDocument();
  expect(screen.queryByText(`后台研判任务报告：${problem}`)).toBeNull();
});

test("代码仓库密钥研判单独开关：说明外发内容并随设置提交", async () => {
  mock({ providers: [{ ...LLM_PROVIDER, in_use: "primary" }], settings: { ...LLM_SETTINGS, enabled: true, primary_id: 1 } });
  let saved: Record<string, unknown> | null = null;
  server.use(
    http.put("*/api/v1/llm/settings", async ({ request }) => {
      saved = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...LLM_SETTINGS, ...saved, updated_at: "2026-10-17T08:00:00Z" });
    }),
  );
  const user = userEvent.setup();
  renderApp(<LlmPage />);
  const toggle = await screen.findByRole("switch", { name: "研判代码仓库密钥" });
  await waitFor(() => expect(toggle).not.toBeDisabled());
  expect(toggle).not.toBeChecked();
  expect(screen.getByText(/密钥原值、邮箱与私密关键词不会发送/)).toBeInTheDocument();
  await user.click(toggle);
  await user.click(screen.getByText("保存"));
  await waitFor(() => expect(saved).not.toBeNull());
  expect(saved).toMatchObject({ enabled: true, primary_id: 1, code_enabled: true });
});
