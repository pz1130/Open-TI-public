import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import SocialAccountsPage from "./SocialAccountsPage";
import { ME_ANALYST, ME_VIEWER } from "../test/fixtures";
import { renderApp } from "../test/render";
import { server } from "../test/server";

const ACCOUNT = {
  id: 1, platform: "bluesky", handle: "sbrank.bsky.social", label: "官方账号", extra_queries: [], allowed_accounts: [], enabled: true,
  platform_id: "did:plc:official", display_name: "Sample Brand", has_avatar: true, profile_checked_at: "2026-10-14T01:00:00Z",
  created_at: "2026-10-14T00:00:00Z", next_check_at: "2026-10-15T01:00:00Z", last_checked_at: "2026-10-14T01:00:00Z",
  scanning: false, error: null, adapter_ready: true, candidate_count: 2,
};
const BAD = {
  id: 7, platform_account_id: "did:plc:bad", handle: "sbrank-support.bsky.social", display_name: "Sample Brand",
  profile_url: "https://bsky.app/profile/did:plc:bad", registered_at: "2026-10-10T00:00:00Z", score: 75, severity: "high",
  signals: ["display_same", "avatar"], first_seen: "2026-10-14T01:00:00Z", last_seen: "2026-10-14T01:00:00Z",
  gone_at: null, finding_id: 3, alert_id: 9, allowed: false,
};
const FAN = { ...BAD, id: 8, platform_account_id: "did:plc:fan", handle: "sbrank.fans.bsky.social", profile_url: "https://bsky.app/profile/did:plc:fan", score: 25, severity: "low", signals: ["handle_same"], finding_id: 4, alert_id: null };

function serve(account: object = ACCOUNT, me = ME_ANALYST) {
  server.use(
    http.get("*/api/v1/auth/me", () => HttpResponse.json(me)),
    http.get("*/api/v1/protected-accounts", () => HttpResponse.json({ items: [account], next_cursor: null })),
    http.get("*/api/v1/protected-accounts/1/candidates", () => HttpResponse.json({ items: [BAD, FAN], next_cursor: null })),
  );
}

test("列表显示平台资料与状态，查看候选的信号、告警与已消失", async () => {
  serve({ ...ACCOUNT, error: "profile_failed; search_failed:1" });
  const user = userEvent.setup();
  renderApp(<SocialAccountsPage />);
  expect(await screen.findByText("sbrank.bsky.social")).toBeInTheDocument();
  expect(screen.getByText("Sample Brand")).toBeInTheDocument();
  await user.hover(screen.getByText("部分检查未成功"));
  expect(await screen.findByText(/未能读取受保护账号资料/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "查看候选" }));
  const drawer = await screen.findByRole("dialog");
  expect(await within(drawer).findByText("sbrank-support.bsky.social")).toHaveAttribute("href", "https://bsky.app/profile/did:plc:bad");
  expect(within(drawer).getByText("头像相似")).toBeInTheDocument();
  expect(within(drawer).getByRole("link", { name: "#9" })).toHaveAttribute("href", "/alerts/9");
});

test("添加受保护账号：平台、账号名、补充搜索词与已知合法账号", async () => {
  serve();
  let saved: unknown;
  server.use(http.post("*/api/v1/protected-accounts", async ({ request }) => { saved = await request.json(); return HttpResponse.json(ACCOUNT, { status: 201 }); }));
  const user = userEvent.setup();
  renderApp(<SocialAccountsPage />);
  await user.click(await screen.findByRole("button", { name: "添加受保护账号" }));
  await user.click(screen.getByLabelText("Mastodon"));
  await user.type(screen.getByLabelText("账号名"), "sbrank@mastodon.social");
  await user.type(screen.getByLabelText("备注"), "官方账号");
  await user.type(screen.getByLabelText("补充搜索词"), "样本银行\n样本品牌");
  await user.type(screen.getByLabelText("已知合法账号"), "sbr-fans@mastodon.social");
  await user.click(screen.getByRole("button", { name: "确定" }));
  await waitFor(() => expect(saved).toEqual({
    platform: "mastodon", handle: "sbrank@mastodon.social", label: "官方账号", enabled: true,
    extra_queries: ["样本银行", "样本品牌"], allowed_accounts: ["sbr-fans@mastodon.social"],
  }));
});

test("把候选标为合法账号会把永久 ID 加入名单", async () => {
  serve();
  let saved: { allowed_accounts?: string[] } | undefined;
  server.use(http.put("*/api/v1/protected-accounts/1", async ({ request }) => { saved = await request.json() as typeof saved; return HttpResponse.json(ACCOUNT); }));
  const user = userEvent.setup();
  renderApp(<SocialAccountsPage />);
  await user.click(await screen.findByRole("button", { name: "查看候选" }));
  const drawer = await screen.findByRole("dialog");
  const row = (await within(drawer).findByText("sbrank.fans.bsky.social")).closest("tr") as HTMLElement;
  await user.click(within(row).getByRole("button", { name: "标为合法账号" }));
  await user.click(await screen.findByRole("button", { name: "确定" }));
  await waitFor(() => expect(saved?.allowed_accounts).toEqual(["did:plc:fan"]));
});

test("低危候选可提升为告警，预填主页链接与冒充账号类别", async () => {
  serve();
  server.use(http.get("*/api/v1/submissions/platform", () => HttpResponse.json({
    url: "https://bsky.app/profile/did:plc:fan", platform: "bluesky", platform_name: "Bluesky", fetch: false, error: null,
  })));
  const user = userEvent.setup();
  renderApp(<SocialAccountsPage />);
  await user.click(await screen.findByRole("button", { name: "查看候选" }));
  const drawer = await screen.findByRole("dialog");
  const row = (await within(drawer).findByText("sbrank.fans.bsky.social")).closest("tr") as HTMLElement;
  expect(within(within(drawer).getByText("sbrank-support.bsky.social").closest("tr") as HTMLElement).queryByRole("button", { name: "提升为告警" })).toBeNull();
  await user.click(within(row).getByRole("button", { name: "提升为告警" }));
  expect(await screen.findByDisplayValue("https://bsky.app/profile/did:plc:fan")).toBeInTheDocument();
  expect(screen.getByLabelText("冒充账号")).toBeChecked();
});

test("适配器未批准时提示到连接器设置", async () => {
  serve({ ...ACCOUNT, adapter_ready: false });
  renderApp(<SocialAccountsPage />);
  expect(await screen.findByText("平台适配器未启用")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "连接器设置" })).toHaveAttribute("href", "/connectors");
});

test("只读用户不能添加、修改、检查或标记", async () => {
  serve(ACCOUNT, ME_VIEWER);
  const user = userEvent.setup();
  renderApp(<SocialAccountsPage />);
  expect(await screen.findByText("sbrank.bsky.social")).toBeInTheDocument();
  for (const name of ["添加受保护账号", "立即检查", "编辑", "删除"]) {
    expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
  }
  await user.click(screen.getByRole("button", { name: "查看候选" }));
  const drawer = await screen.findByRole("dialog");
  await within(drawer).findByText("sbrank.fans.bsky.social");
  expect(within(drawer).queryByRole("button", { name: "标为合法账号" })).toBeNull();
  expect(within(drawer).queryByRole("button", { name: "提升为告警" })).toBeNull();
});
