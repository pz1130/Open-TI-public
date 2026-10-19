import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "../test/render";
import { CATALOG, CATALOG_BY_TYPE, type Widget } from "./catalog";
import { AddWidgetDrawer, ParamsModal } from "./editors";

test("卡片满了时添加按钮不可用并给出提示", async () => {
  const added: string[] = [];
  renderApp(<AddWidgetDrawer open full defs={CATALOG} onClose={() => {}} onAdd={(d) => added.push(d.type)} />);
  expect(await screen.findByText("最多 30 张卡片，请先移除一些")).toBeInTheDocument();
  const row = document.querySelector('[data-widget-type="trend"]') as HTMLElement;
  const add = within(row).getByText("添加", { selector: "button span" }).closest("button") as HTMLButtonElement;
  expect(add).toBeDisabled();
});

test("条数输入框按卡片上限限制", async () => {
  const widget: Widget = { id: "n", type: "networks", x: 0, y: 0, w: 6, h: 5, params: { days: null, limit: null } };
  const got: Widget["params"][] = [];
  const user = userEvent.setup();
  renderApp(<ParamsModal widget={widget} onCancel={() => {}} onOk={(p) => got.push(p)} />);
  const input = await screen.findByRole("spinbutton");
  expect(input).toHaveAttribute("aria-valuemax", String(CATALOG_BY_TYPE.networks.maxLimit));
  await user.type(input, "40");
  await user.click(within(input.closest('[role="dialog"]') as HTMLElement).getByText(/确\s*定|OK/, { selector: "button span" }));
  await waitFor(() => expect(got).toHaveLength(1));
  expect(got[0].limit).toBe(10); // 超出上限按上限保存
});
