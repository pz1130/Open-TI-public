import type { ComponentType } from "react";
import type { WidgetProps } from "./common";
import { CampaignsWidget, ConnectorHealthWidget, MyTodoWidget, TakedownsWidget } from "./operations";
import {
  ByCategoryWidget,
  BySourceWidget,
  CountriesWidget,
  MttdWidget,
  NetworksWidget,
  OverdueWidget,
  StatWidget,
  TopWidget,
  TrendWidget,
} from "./overview";

export type { WidgetProps } from "./common";

/** 卡片类型 → 渲染组件；与 catalog.ts 的 CATALOG 一一对应（widgets.test.tsx 检查）。 */
export const WIDGETS: Record<string, ComponentType<WidgetProps>> = {
  stat: StatWidget,
  trend: TrendWidget,
  mttd: MttdWidget,
  by_category: ByCategoryWidget,
  by_source: BySourceWidget,
  overdue: OverdueWidget,
  top: TopWidget,
  countries: CountriesWidget,
  networks: NetworksWidget,
  my_todo: MyTodoWidget,
  takedowns: TakedownsWidget,
  campaigns: CampaignsWidget,
  connector_health: ConnectorHealthWidget,
};
