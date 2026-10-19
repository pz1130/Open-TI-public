import { screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { vi } from "vitest";
import { renderApp } from "../test/render";
import { server } from "../test/server";
import * as context from "./projectContext";
import ProjectStatus from "./ProjectStatus";

test("普通用户看到项目变化时重新加载，避免保留旧项目缓存", async () => {
  let project = "sbr";
  const reload = vi.spyOn(context, "reloadProject").mockImplementation(() => {});
  server.use(http.get("*/api/v1/projects/current", () => HttpResponse.json({ project_id: project, rules_version: 1 })));
  const { client } = renderApp(<ProjectStatus admin={false} />);
  expect(await screen.findByText("当前项目：sbr")).toBeInTheDocument();
  expect(screen.queryByRole("button")).not.toBeInTheDocument();
  expect(reload).not.toHaveBeenCalled();
  project = "second";
  await client.invalidateQueries({ queryKey: ["active-project"] });
  await waitFor(() => expect(reload).toHaveBeenCalledWith(false));
  reload.mockRestore();
});
