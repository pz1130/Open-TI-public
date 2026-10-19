import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { vi } from "vitest";
import { renderApp } from "../test/render";
import { server } from "../test/server";
import { ME_CONFIG_ADMIN, ME_CONFIG_VIEWER } from "../test/fixtures";
import { can } from "../auth/perms";
import * as context from "../shell/projectContext";
import { SECTIONS } from "./sections";
import ProjectsTab from "./ProjectsTab";

const PROJECTS = {
  active_project: "sbr", rules_version: 7, total: 3,
  items: [
    { project_id: "sbr", name: "SBR", active: true, available: true },
    { project_id: "second", name: "Second project", active: false, available: true },
    { project_id: "missing", name: "Missing rules", active: false, available: false },
  ],
};

beforeEach(() => server.use(http.get("*/api/v1/admin/projects", () => HttpResponse.json(PROJECTS))));

test("只有管理员能进入项目切换；当前项目和缺少规则的项目不可切换", async () => {
  const item = SECTIONS.flatMap((section) => section.items).find((section) => section.kind === "projects")!;
  expect(can(ME_CONFIG_ADMIN, item.perm!)).toBe(true);
  expect(can(ME_CONFIG_VIEWER, item.perm!)).toBe(false);
  renderApp(<ProjectsTab />);
  expect(await screen.findByText("当前项目：sbr")).toBeInTheDocument();
  expect(within(screen.getByRole("row", { name: /SBR sbr/ })).getByRole("button", { name: "切换项目" })).toBeDisabled();
  expect(within(screen.getByRole("row", { name: /Missing rules/ })).getByRole("button", { name: "切换项目" })).toBeDisabled();
  expect(screen.getByRole("combobox", { name: "每页显示条数" })).toBeInTheDocument();
});

test("展示全平台影响，确认后携带版本切换并清除旧页面", async () => {
  let body: unknown;
  const reload = vi.spyOn(context, "reloadProject").mockImplementation(() => {});
  server.use(http.post("*/api/v1/admin/projects/activate", async ({ request }) => {
    body = await request.json();
    return HttpResponse.json({ project_id: "second", rules_version: 8 });
  }));
  const user = userEvent.setup();
  renderApp(<ProjectsTab />);
  await user.click(await within(await screen.findByRole("row", { name: /Second project/ })).findByRole("button", { name: "切换项目" }));
  const modal = screen.getByRole("dialog");
  expect(within(modal).getByText(/影响所有用户/)).toBeInTheDocument();
  expect(body).toBeUndefined();
  await user.click(within(modal).getByRole("button", { name: "切换项目" }));
  await waitFor(() => expect(reload).toHaveBeenCalledWith(true));
  expect(body).toEqual({ project_id: "second", base_version: 7 });
  reload.mockRestore();
});

test("版本冲突不重试，必须刷新列表后重新选择", async () => {
  let calls = 0;
  server.use(http.post("*/api/v1/admin/projects/activate", () => {
    calls++;
    return HttpResponse.json({ detail: { reason: "version_conflict", current_version: 8 } }, { status: 409 });
  }));
  const user = userEvent.setup();
  renderApp(<ProjectsTab />);
  await user.click(within(await screen.findByRole("row", { name: /Second project/ })).getByRole("button", { name: "切换项目" }));
  await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "切换项目" }));
  expect(await screen.findByText(/规则或当前项目已被其他管理员修改/)).toBeInTheDocument();
  expect(calls).toBe(1);
  await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "刷新" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
});
