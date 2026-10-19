import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import SettingsPage from "./SettingsPage";
import { ALERTING_SECRETS, CONFIG_ALERTING, CONFIG_CAMPAIGNS, CONFIG_ORG, CONFIG_RETENTION, CONFIG_RULES, CONFIG_STATUS, ME_ALERTING_ADMIN, ME_CONFIG_ADMIN, ME_CONFIG_ANALYST, ME_CONFIG_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

function mock(me = ME_CONFIG_ADMIN) {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(me)),
    http.get("*/api/v1/config/status", () => HttpResponse.json(CONFIG_STATUS)),
    http.get("*/api/v1/config/organization", () => HttpResponse.json(CONFIG_ORG)),
    http.get("*/api/v1/config/retention", () => HttpResponse.json(CONFIG_RETENTION)),
    http.get("*/api/v1/config/campaigns", () => HttpResponse.json(CONFIG_CAMPAIGNS)),
    http.get("*/api/v1/config/rules", () => HttpResponse.json(CONFIG_RULES)),
    http.get("*/api/v1/config/:kind/revisions", () => HttpResponse.json([])),
  );
}

test("只读用户只看到机构信息且不能保存", async () => {
  mock(ME_CONFIG_VIEWER);
  renderApp(<SettingsPage />);
  await userEvent.setup().click(await screen.findByRole("menuitem", { name: "机构信息" }));
  expect(await screen.findByLabelText("机构名称")).toHaveValue("Example Organization");
  expect(screen.queryByRole("menuitem", { name: "关键词规则" })).toBeNull();
  expect(screen.queryByRole("button", { name: "保存" })).toBeNull();
  expect(screen.queryByRole("menuitem", { name: "凭据加密主密钥" })).toBeNull();
  expect(screen.queryByRole("menuitem", { name: "登录与单点登录" })).toBeNull();
  expect(screen.queryByRole("menuitem", { name: "业务运行参数" })).toBeNull();
});

test("分组导航：只读用户看不到关键词规则，深链接落在保留期", async () => {
  mock(ME_CONFIG_VIEWER);
  renderApp(<SettingsPage />, { route: "/settings/retention" });
  expect(await screen.findByLabelText("原始采集数据")).toHaveValue("90");
  expect(screen.queryByRole("menuitem", { name: "关键词规则" })).toBeNull();
  expect(screen.getByText("监测")).toBeInTheDocument();
  expect(screen.getByText("平台")).toBeInTheDocument();
});

test("调短保留期：超过一轮上限时标出至少多少并说明后续还会删除", async () => {
  mock(ME_CONFIG_ADMIN);
  server.use(http.put("*/api/v1/config/retention", () =>
    HttpResponse.json({ detail: { reason: "retention_shortened", preview_error: null, preview_capped: true,
      preview: { findings: 4990, cases: 10, alerts: 12, connector_runs: 7 } } }, { status: 409 })));
  const user = userEvent.setup();
  renderApp(<SettingsPage />, { route: "/settings/retention" });
  const cases = await screen.findByLabelText("有告警的案件");
  await user.clear(cases);
  await user.type(cases, "600");
  await user.click(screen.getByRole("button", { name: "保存" }));
  expect(await screen.findByText(/没有告警的发现：≥ 4990/)).toBeInTheDocument();
  expect(screen.getByText(/告警：≥ 12/)).toBeInTheDocument();
  expect(screen.getByText(/连接器运行记录：7/)).toBeInTheDocument();
  expect(screen.getByText(/之后的清理会继续删除/)).toBeInTheDocument();
});

test("调短保留期：确认弹窗列出预览数量后提交", async () => {
  mock(ME_CONFIG_ADMIN);
  const bodies: Record<string, unknown>[] = [];
  server.use(http.put("*/api/v1/config/retention", async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    bodies.push(body);
    return body.confirm_retention
      ? HttpResponse.json({ ...CONFIG_RETENTION, version: 1 })
      : HttpResponse.json({ detail: { reason: "retention_shortened", preview_error: null,
          preview: { findings: 12, cases: 3, alerts: 4, raw_item_partitions: 2, raw_items_estimate: 50000 } } }, { status: 409 });
  }));
  const user = userEvent.setup();
  renderApp(<SettingsPage />, { route: "/settings/retention" });
  const cases = await screen.findByLabelText("有告警的案件");
  await user.clear(cases);
  await user.type(cases, "600");
  await user.click(screen.getByRole("button", { name: "保存" }));
  expect(await screen.findByText(/有告警的案件：3/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "确认删除并保存" }));
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[1]).toMatchObject({ confirm_retention: true, data: { cases_days: 600 } });
});

test("仿冒活动参数保存后提示正在重算", async () => {
  mock(ME_CONFIG_ADMIN);
  server.use(http.put("*/api/v1/config/campaigns", () => HttpResponse.json({ ...CONFIG_CAMPAIGNS, version: 1 })));
  const user = userEvent.setup();
  renderApp(<SettingsPage />, { route: "/settings/campaigns" });
  const share = await screen.findByLabelText("共享上限");
  await user.clear(share);
  await user.type(share, "20");
  await user.click(screen.getByRole("button", { name: "保存" }));
  expect(await screen.findByText("已保存，仿冒活动正在按新参数重算")).toBeInTheDocument();
});

test("切换配置标签后保留尚未保存的规则草稿", async () => {
  mock(ME_CONFIG_ANALYST);
  const user = userEvent.setup();
  renderApp(<SettingsPage />);
  const ref = await screen.findByLabelText("授权编号");
  await user.clear(ref);
  await user.type(ref, "draft-ref");
  await user.click(screen.getByRole("menuitem", { name: "机构信息" }));
  expect(await screen.findByLabelText("机构名称")).toBeInTheDocument();
  await user.click(screen.getByRole("menuitem", { name: "关键词规则" }));
  expect(screen.getByLabelText("授权编号")).toHaveValue("draft-ref");
});

test("没有项目切换权限的分析员不能修改项目标识", async () => {
  mock(ME_CONFIG_ANALYST);
  renderApp(<SettingsPage />);
  expect(await screen.findByLabelText("项目标识")).toHaveAttribute("readonly");
});

test("保存机构信息：提交结构化数据与当前版本号，空网址提交 null", async () => {
  mock();
  let body: Record<string, unknown> | null = null;
  server.use(
    http.put("*/api/v1/config/organization", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...CONFIG_ORG, version: 1, source: "db" });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SettingsPage />);
  await user.click(await screen.findByRole("menuitem", { name: "机构信息" }));
  const name = await screen.findByLabelText("机构名称");
  await user.clear(name);
  await user.type(name, "Acme");
  await user.type(within(screen.getByTestId("settings-active")).getByPlaceholderText("保存说明（选填）"), "改名");
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).not.toBeNull());
  expect(body).toMatchObject({ base_version: 0, note: "改名", data: { name: "Acme", website: null } });
});

test("版本冲突时提示对方并保留草稿", async () => {
  mock();
  server.use(
    http.put("*/api/v1/config/organization", () =>
      HttpResponse.json({ detail: { reason: "version_conflict", current_version: 2, updated_by: "bob" } }, { status: 409 }),
    ),
  );
  const user = userEvent.setup();
  renderApp(<SettingsPage />);
  await user.click(await screen.findByRole("menuitem", { name: "机构信息" }));
  const name = await screen.findByLabelText("机构名称");
  await user.clear(name);
  await user.type(name, "Draft");
  await user.click(screen.getByRole("button", { name: "保存" }));
  expect(await screen.findByText(/配置已被 bob 更新到 v2/)).toBeInTheDocument();
  expect(screen.getByLabelText("机构名称")).toHaveValue("Draft");
});

test("载入最新版本成功后清除冲突提示并显示新内容", async () => {
  mock();
  const latest = { ...CONFIG_ORG, version: 2, source: "db" as const, created_by: "bob", data: { ...CONFIG_ORG.data, name: "Latest Org" } };
  let current = CONFIG_ORG;
  server.use(
    http.get("*/api/v1/config/organization", () => HttpResponse.json(current)),
    http.put("*/api/v1/config/organization", () => {
      current = latest;
      return HttpResponse.json({ detail: { reason: "version_conflict", current_version: 2, updated_by: "bob" } }, { status: 409 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SettingsPage />);
  await user.click(await screen.findByRole("menuitem", { name: "机构信息" }));
  const name = await screen.findByLabelText("机构名称");
  await user.clear(name);
  await user.type(name, "Draft");
  await user.click(screen.getByRole("button", { name: "保存" }));
  expect(await screen.findByText(/配置已被 bob 更新到 v2/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "放弃草稿并载入最新版本" }));
  await waitFor(() => expect(screen.queryByText(/配置已被 bob 更新到 v2/)).toBeNull());
  expect(screen.getByLabelText("机构名称")).toHaveValue("Latest Org");
});

test("重新拉取失败时保留已加载的表单和冲突提示", async () => {
  mock();
  server.use(
    http.put("*/api/v1/config/organization", () =>
      HttpResponse.json({ detail: { reason: "version_conflict", current_version: 2, updated_by: "bob" } }, { status: 409 }),
    ),
  );
  const user = userEvent.setup();
  const { client } = renderApp(<SettingsPage />);
  await user.click(await screen.findByRole("menuitem", { name: "机构信息" }));
  const name = await screen.findByLabelText("机构名称");
  await user.clear(name);
  await user.type(name, "Draft");
  await user.click(screen.getByRole("button", { name: "保存" }));
  expect(await screen.findByText(/配置已被 bob 更新到 v2/)).toBeInTheDocument();
  server.use(http.get("*/api/v1/config/organization", () => new HttpResponse(null, { status: 500 })));
  await client.invalidateQueries({ queryKey: ["config", "organization"], exact: true });
  await waitFor(() => expect(client.getQueryState(["config", "organization"])?.status).toBe("error"));
  // 查询缓存先于界面更新；React Query 用 setTimeout 通知，等这次绘制后再断言。
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 50));
  });
  expect(screen.queryByText(/操作失败/)).toBeNull();
  expect(screen.getByLabelText("机构名称")).toHaveValue("Draft");
  expect(screen.getByText(/配置已被 bob 更新到 v2/)).toBeInTheDocument();
});

test("状态条区分已生效、加载中、错误与未响应", async () => {
  mock(ME_CONFIG_ANALYST);
  const user = userEvent.setup();
  renderApp(<SettingsPage />);
  await user.click(await screen.findByRole("menuitem", { name: "关键词规则" }));
  const bar = await screen.findByTestId("config-status-rules");
  expect(within(bar).getByText("api@h · v3").closest("[data-state]")).toHaveAttribute("data-state", "applied");
  expect(within(bar).getByText("worker@h · v2").closest("[data-state]")).toHaveAttribute("data-state", "pending");
  expect(within(bar).getByText("stream-certstream@h · v2").closest("[data-state]")).toHaveAttribute("data-state", "error");
  expect(within(bar).getByText("intake@e · v1").closest("[data-state]")).toHaveAttribute("data-state", "stale");
});

test("YAML 无法通过校验时停留在 YAML 模式并显示行号", async () => {
  mock(ME_CONFIG_ANALYST);
  server.use(
    http.post("*/api/v1/config/rules/validate", async ({ request }) => {
      const b = (await request.json()) as { yaml?: string; data?: unknown };
      return b.yaml !== undefined
        ? HttpResponse.json({ ok: false, errors: [{ path: "", message: "YAML 语法错误", line: 2 }] })
        : HttpResponse.json({ ok: true, yaml: CONFIG_RULES.yaml, data: CONFIG_RULES.data, errors: [] });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SettingsPage />);
  await user.click(await screen.findByRole("radio", { name: "YAML" }));
  const editor = await screen.findByLabelText("规则 YAML");
  await user.clear(editor);
  await user.type(editor, "project: [[");  // user-event 中 "[[" 输入一个 "["
  await user.click(screen.getByRole("radio", { name: "表单" }));
  expect(await screen.findByText(/第 2 行/)).toBeInTheDocument();
  expect(screen.getByLabelText("规则 YAML")).toBeInTheDocument();
});

test("修改项目标识需确认，确认后带 confirm_project_change 重新提交", async () => {
  mock({ ...ME_CONFIG_ANALYST, permissions: [...ME_CONFIG_ANALYST.permissions, "projects:write"] });
  const bodies: Record<string, unknown>[] = [];
  server.use(
    http.put("*/api/v1/config/rules", async ({ request }) => {
      const b = (await request.json()) as Record<string, unknown>;
      bodies.push(b);
      return b.confirm_project_change
        ? HttpResponse.json({ ...CONFIG_RULES, version: 4 })
        : HttpResponse.json({ detail: { reason: "project_change", from: "sbr", to: "acme", alert_count: 12 } }, { status: 409 });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SettingsPage />);
  const project = await screen.findByLabelText("项目标识");
  await user.clear(project);
  await user.type(project, "acme");
  await user.click(screen.getByRole("button", { name: "保存" }));
  expect(await screen.findByText(/当前项目 sbr 下有 12 条告警/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "确认修改" }));
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[0]).toMatchObject({ base_version: 3, data: { project: "acme" } });
  expect(bodies[1]).toMatchObject({ confirm_project_change: true });
});

test("试跑把表单草稿转成 YAML 后提交到规则沙箱", async () => {
  mock(ME_CONFIG_ANALYST);
  let tested: Record<string, unknown> | null = null;
  server.use(
    http.post("*/api/v1/config/rules/validate", () =>
      HttpResponse.json({ ok: true, yaml: "project: sbr\n", data: CONFIG_RULES.data, errors: [] }),
    ),
    http.post("*/api/v1/rules/test", async ({ request }) => {
      tested = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ source: "draft", project: "sbr", domains: [], text_hits: [
        { set_name: "brand", term: "Sample Brand", mode: "phrase", role: "match", context: "…Sample Brand…" },
      ] });
    }),
  );
  const user = userEvent.setup();
  renderApp(<SettingsPage />);
  await user.type(await screen.findByLabelText("样例文本"), "Sample Brand loans");
  await user.click(screen.getByRole("button", { name: "试跑" }));
  expect(await screen.findByText("brand · Sample Brand")).toBeInTheDocument();
  expect(tested).toMatchObject({ draft_yaml: "project: sbr\n", text: "Sample Brand loans" });
});

function mockAlerting(me = ME_ALERTING_ADMIN, secrets = ALERTING_SECRETS) {
  mock(me);
  server.use(
    http.get("*/api/v1/config/alerting", () => HttpResponse.json(CONFIG_ALERTING)),
    http.get("*/api/v1/config/alerting/secrets", () => HttpResponse.json(secrets)),
  );
}

async function openAlerting(user: ReturnType<typeof userEvent.setup>) {
  renderApp(<SettingsPage />);
  await user.click(await screen.findByRole("menuitem", { name: "告警推送" }));
}

test("密钥输入框显示已设置、来自环境变量与未设置", async () => {
  mockAlerting();
  const user = userEvent.setup();
  await openAlerting(user);
  expect(await screen.findByText("已设置 ••••1234")).toBeInTheDocument();
  expect(screen.getByText("来自环境变量")).toBeInTheDocument();
  expect(screen.getByText("未设置")).toBeInTheDocument();
});

test("服务器缺主密钥时密钥输入框禁用并提示", async () => {
  mockAlerting(ME_ALERTING_ADMIN, { ...ALERTING_SECRETS, encryption_key: false });
  const user = userEvent.setup();
  await openAlerting(user);
  const hook = await screen.findByLabelText("Webhook 地址");
  await waitFor(() => expect(hook).toBeDisabled());
  expect(hook).toHaveAttribute("placeholder", "尚未初始化凭据加密主密钥，请由管理员前往「配置 → 管理员 → 凭据加密主密钥」完成初始化");
});

test("新增 Teams 渠道：ID 由名称生成，提交配置与新 Webhook", async () => {
  mockAlerting();
  let body: Record<string, unknown> | null = null;
  server.use(
    http.put("*/api/v1/config/alerting", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...CONFIG_ALERTING, version: 3 });
    }),
  );
  const user = userEvent.setup();
  await openAlerting(user);
  await user.click(await screen.findByRole("button", { name: "添加 Teams 渠道" }));
  const names = screen.getAllByLabelText("渠道名称");
  await user.type(names[names.length - 1], "Brand Team");
  const ids = screen.getAllByLabelText("渠道 ID");
  expect(ids[ids.length - 1]).toHaveValue("brand-team");
  expect(ids[0]).toBeDisabled(); // 已保存的渠道 ID 只读
  const hooks = screen.getAllByLabelText("Webhook 地址");
  await user.type(hooks[hooks.length - 1], "https://hook.example/new");
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).not.toBeNull());
  expect(body).toMatchObject({
    base_version: 2,
    secrets: { "channel:brand-team:webhook_url": "https://hook.example/new" },
    data: { channels: [{ id: "secops" }, { id: "brand-team", type: "teams" }] },
  });
});

test("未保存渠道改 ID 后，保存用新的密钥键并丢掉旧键", async () => {
  mockAlerting();
  let body: Record<string, unknown> | null = null;
  server.use(
    http.put("*/api/v1/config/alerting", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...CONFIG_ALERTING, version: 3 });
    }),
  );
  const user = userEvent.setup();
  await openAlerting(user);
  await user.click(await screen.findByRole("button", { name: "添加 Teams 渠道" }));
  await user.type(screen.getAllByLabelText("渠道名称").at(-1)!, "Brand Team");
  const id = screen.getAllByLabelText("渠道 ID").at(-1)!;
  expect(id).toHaveValue("brand-team");
  expect(id).toBeEnabled();
  await user.type(screen.getAllByLabelText("Webhook 地址").at(-1)!, "https://hook.example/moved");
  await user.clear(id);
  await user.type(id, "oncall");
  expect(id).toHaveValue("oncall");
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).not.toBeNull());
  const saved = body as unknown as { secrets?: Record<string, string>; data?: { channels?: { id?: string }[] } };
  expect(Object.keys(saved.secrets ?? {})).toEqual(["channel:oncall:webhook_url"]);
  expect(saved.secrets?.["channel:oncall:webhook_url"]).toBe("https://hook.example/moved");
  expect(saved.data?.channels?.map((c) => c.id)).toEqual(["secops", "oncall"]);
});

test("删除未保存渠道时不提交它的密钥草稿", async () => {
  mockAlerting();
  let body: Record<string, unknown> | null = null;
  server.use(
    http.put("*/api/v1/config/alerting", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...CONFIG_ALERTING, version: 3 });
    }),
  );
  const user = userEvent.setup();
  await openAlerting(user);
  await user.click(await screen.findByRole("button", { name: "添加 Teams 渠道" }));
  await user.type(screen.getAllByLabelText("渠道名称").at(-1)!, "Brand Team");
  await user.type(screen.getAllByLabelText("Webhook 地址").at(-1)!, "https://hook.example/moved");
  const removes = screen.getAllByRole("button", { name: "删除渠道" });
  await user.click(removes.at(-1)!);
  await user.click(screen.getByRole("button", { name: "保存" }));
  await waitFor(() => expect(body).not.toBeNull());
  expect(body).not.toHaveProperty("secrets");
  expect(body).toMatchObject({ data: { channels: [{ id: "secops" }] } });
});

test("发送测试显示成功与脱敏后的失败原因", async () => {
  mockAlerting();
  let calls = 0;
  server.use(
    http.post("*/api/v1/config/alerting/test", () =>
      HttpResponse.json(++calls === 1 ? { ok: true, error: null } : { ok: false, error: "HTTP 403" }),
    ),
  );
  const user = userEvent.setup();
  await openAlerting(user);
  await user.click(await screen.findByRole("button", { name: "发送测试" }));
  expect(await screen.findByText("测试消息已发送")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "发送测试" }));
  expect(await screen.findByText("发送失败：HTTP 403")).toBeInTheDocument();
});

test("访问地址变化需确认单点登录回调", async () => {
  mockAlerting();
  const bodies: Record<string, unknown>[] = [];
  server.use(
    http.put("*/api/v1/config/alerting", async ({ request }) => {
      const b = (await request.json()) as Record<string, unknown>;
      bodies.push(b);
      return b.confirm_oidc_change
        ? HttpResponse.json(CONFIG_ALERTING)
        : HttpResponse.json({ detail: { reason: "oidc_redirect_change", redirect_uri: "https://new.example/api/v1/auth/oidc/callback" } }, { status: 409 });
    }),
  );
  const user = userEvent.setup();
  await openAlerting(user);
  const url = await screen.findByLabelText("平台访问地址");
  await user.clear(url);
  await user.type(url, "https://new.example");
  await user.click(screen.getByRole("button", { name: "保存" }));
  expect(await screen.findByText(/https:\/\/new\.example\/api\/v1\/auth\/oidc\/callback/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "确认修改" }));
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[1]).toMatchObject({ confirm_oidc_change: true });
});

test("非平台管理员只读且看不到密钥", async () => {
  mockAlerting(ME_CONFIG_ANALYST);
  const user = userEvent.setup();
  await openAlerting(user);
  expect(await screen.findByLabelText("平台访问地址")).toBeDisabled();
  expect(screen.queryByRole("button", { name: "保存" })).toBeNull();
  expect(screen.queryByRole("button", { name: "发送测试" })).toBeNull();
  expect(screen.queryByText("已设置 ••••1234")).toBeNull();
});

test("仅有用户管理权限时可进入用户管理，不能进入权限定义或其他管理员设置", async () => {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json({ ...ME_CONFIG_VIEWER, roles: [], permissions: ["users:write"] })),
    http.get("*/api/v1/admin/users", () => HttpResponse.json({ items: [], total: 0 })),
    http.get("*/api/v1/admin/access", () => HttpResponse.json({ roles: [], permission_sets: [], permissions: [] })),
  );
  renderApp(<SettingsPage />, { route: "/settings/access" });
  expect(await screen.findByRole("button", { name: "创建本地用户" })).toBeInTheDocument();
  expect(screen.getByRole("menuitem", { name: "用户管理" })).toBeInTheDocument();
  expect(screen.queryByRole("menuitem", { name: "角色与权限集" })).not.toBeInTheDocument();
  expect(screen.queryByRole("menuitem", { name: "凭据加密主密钥" })).not.toBeInTheDocument();
  expect(screen.queryByRole("menuitem", { name: "机构信息" })).not.toBeInTheDocument();
});
