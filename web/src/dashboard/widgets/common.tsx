import type { UseQueryResult } from "@tanstack/react-query";
import { Spin } from "antd";
import type { ReactNode } from "react";
import QueryError from "../../components/QueryError";
import { DEFAULT_LIMIT, type Widget } from "../catalog";

/** days 是页面当前的全局天数；卡片参数为 null 时跟随它。 */
export interface WidgetProps {
  widget: Widget;
  days: number;
}

export const numParam = (w: Widget, name: string): number | null => {
  const v = w.params[name];
  return typeof v === "number" ? v : null;
};

export const strParam = (w: Widget, name: string): string | null => {
  const v = w.params[name];
  return typeof v === "string" ? v : null;
};

export const limitOf = (w: Widget) => numParam(w, "limit") ?? DEFAULT_LIMIT;

/** 卡片内的加载 / 出错状态：出错只影响这一张卡片。 */
export function Loaded<T>({ q, children }: { q: UseQueryResult<T>; children: (data: T) => ReactNode }) {
  if (q.error) return <QueryError error={q.error} />;
  if (q.data === undefined) return <Spin />;
  return <>{children(q.data)}</>;
}
