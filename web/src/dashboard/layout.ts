import { CATALOG, CATALOG_BY_TYPE, DAY_OPTIONS, GRID_COLS, MAX_H, MAX_WIDGETS, METRICS, defaultParams, type Layout, type ParamName, type Widget, type WidgetDef } from "./catalog";

type ParamValue = Widget["params"][string];

function validParam(name: ParamName, v: ParamValue, d: WidgetDef): boolean {
  if (v === null) return name !== "metric";
  switch (name) {
    case "days":
      return (DAY_OPTIONS as readonly unknown[]).includes(v);
    case "limit":
      return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= d.maxLimit;
    case "category":
      return typeof v === "string" && v.length > 0;
    case "metric":
      return (METRICS as readonly unknown[]).includes(v);
  }
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, Number.isFinite(v) ? Math.round(v) : lo));

/**
 * 把服务器返回的布局整理成当前用户可显示的样子：
 * 丢弃不认识的类型、allowed 返回 false 的类型和重复 id；坐标限制在网格内；参数不合法时退回初值，多余参数删除。
 */
export function normalize(layout: Layout, allowed: (d: WidgetDef) => boolean): Layout {
  const seen = new Set<string>();
  const widgets: Widget[] = [];
  for (const w of layout.widgets) {
    const d = CATALOG_BY_TYPE[w.type];
    if (!d || !allowed(d) || seen.has(w.id)) continue;
    seen.add(w.id);
    const width = clamp(w.w, d.minW, GRID_COLS);
    const fallback = defaultParams(d);
    widgets.push({
      id: w.id,
      type: w.type,
      w: width,
      x: clamp(w.x, 0, GRID_COLS - width),
      h: clamp(w.h, d.minH, MAX_H),
      y: clamp(w.y, 0, 500),
      params: Object.fromEntries(d.params.map((p) => [p, validParam(p, w.params?.[p] ?? null, d) ? (w.params?.[p] ?? null) : fallback[p]])),
    });
  }
  return { version: 1, days: (DAY_OPTIONS as readonly number[]).includes(layout.days) ? layout.days : 30, widgets };
}

/**
 * react-grid-layout 回调给出的新坐标写回布局；不认识的 id 忽略。
 * 坐标没有变化时返回原对象，避免网格每次渲染后的回调引起多余的重新渲染。
 */
export interface GridItem {
  i: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

export function applyGrid(layout: Layout, items: readonly GridItem[]): Layout {
  const pos = new Map(items.map((it) => [it.i, it]));
  let changed = false;
  const widgets = layout.widgets.map((w) => {
    const p = pos.get(w.id);
    if (!p || (p.x === w.x && p.y === w.y && p.w === w.w && p.h === w.h)) return w;
    changed = true;
    return { ...w, x: p.x, y: p.y, w: p.w, h: p.h };
  });
  return changed ? { ...layout, widgets } : layout;
}

/** 第一个未被占用的 w1、w2……（id 限 16 个字符）。 */
export function nextId(layout: Layout): string {
  const ids = new Set(layout.widgets.map((w) => w.id));
  let n = 1;
  while (ids.has(`w${n}`)) n += 1;
  return `w${n}`;
}

/** 新卡片放在最底部、靠左；已满 30 张时原样返回。 */
export function addWidget(layout: Layout, d: WidgetDef): Layout {
  if (layout.widgets.length >= MAX_WIDGETS) return layout;
  const bottom = Math.max(0, ...layout.widgets.map((w) => w.y + w.h));
  return { ...layout, widgets: [...layout.widgets, { id: nextId(layout), type: d.type, x: 0, y: bottom, w: d.w, h: d.h, params: defaultParams(d) }] };
}

export function removeWidget(layout: Layout, id: string): Layout {
  return { ...layout, widgets: layout.widgets.filter((w) => w.id !== id) };
}

export function setParams(layout: Layout, id: string, params: Widget["params"]): Layout {
  return { ...layout, widgets: layout.widgets.map((w) => (w.id === id ? { ...w, params } : w)) };
}

/** 窄屏单列：按行再按列排序。 */
export function stackOrder(layout: Layout): Widget[] {
  return [...layout.widgets].sort((a, b) => a.y - b.y || a.x - b.x);
}

/**
 * 内置与机构默认布局对当前用户一张卡片都不剩时（如 platform_admin 只有连接器权限）的起步布局：
 * 每种有权限的卡片各放一张。
 */
export function starterLayout(allowed: (d: WidgetDef) => boolean): Layout {
  return CATALOG.filter(allowed).reduce<Layout>((l, d) => addWidget(l, d), { version: 1, days: 30, widgets: [] });
}
