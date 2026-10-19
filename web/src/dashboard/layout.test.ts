import { BUILTIN_LAYOUT, CATALOG_BY_TYPE, MAX_WIDGETS, type Layout, type Widget } from "./catalog";
import { addWidget, applyGrid, nextId, normalize, removeWidget, setParams, stackOrder } from "./layout";

const all = () => true;
const w = (over: Partial<Widget>): Widget => ({ id: "a", type: "trend", x: 0, y: 0, w: 8, h: 5, params: { days: null, category: null }, ...over });
const L = (...widgets: Widget[]): Layout => ({ version: 1, days: 30, widgets });

test("内置默认布局本身是规整的", () => {
  expect(normalize(BUILTIN_LAYOUT, all)).toEqual(BUILTIN_LAYOUT);
});

test("丢弃未知类型、无权限类型和重复 id", () => {
  const out = normalize(
    L(w({ id: "a" }), w({ id: "b", type: "future_widget" }), w({ id: "a", type: "mttd" }), w({ id: "c", type: "takedowns", params: {} })),
    (d) => d.perm !== "takedown:read",
  );
  expect(out.widgets.map((x) => x.id)).toEqual(["a"]);
});

test("坐标和尺寸限制在网格内", () => {
  const [a, b] = normalize(L(w({ id: "a", x: 10, w: 8, h: 99, y: -3 }), w({ id: "b", type: "stat", w: 1, h: 1, params: { metric: "mttr" } })), all).widgets;
  expect(a).toMatchObject({ x: 4, w: 8, h: 24, y: 0 });
  expect(b).toMatchObject({ w: 2, h: 2 }); // 指标卡最小 2×2
});

test("参数不合法时退回初值，多余参数删除，缺的补上", () => {
  const out = normalize(
    L(
      w({ id: "a", params: { days: 14, category: "phishing_site", extra: 1 } }),
      w({ id: "b", type: "top", params: { limit: 99 } }),
      w({ id: "c", type: "stat", params: { metric: "nope", days: 7 } }),
    ),
    all,
  ).widgets;
  expect(out[0].params).toEqual({ days: null, category: "phishing_site" });
  expect(out[1].params).toEqual({ category: null, limit: null });
  expect(out[2].params).toEqual({ metric: "open_critical", days: 7 });
});

test("全局天数只接受 7 / 30 / 90", () => {
  expect(normalize({ ...L(), days: 14 }, all).days).toBe(30);
  expect(normalize({ ...L(), days: 90 }, all).days).toBe(90);
});

test("网格回调的坐标写回布局", () => {
  const out = applyGrid(L(w({ id: "a" }), w({ id: "b", y: 5 })), [{ i: "b", x: 4, y: 0, w: 8, h: 6 }, { i: "zzz", x: 0, y: 0, w: 1, h: 1 }]);
  expect(out.widgets[0]).toMatchObject({ id: "a", x: 0, y: 0 });
  expect(out.widgets[1]).toMatchObject({ id: "b", x: 4, y: 0, w: 8, h: 6 });
  const same = L(w({ id: "a" }));
  expect(applyGrid(same, [{ i: "a", x: 0, y: 0, w: 8, h: 5 }])).toBe(same); // 没变化时返回原对象
});

test("添加、移除卡片与修改参数", () => {
  const base = L(w({ id: "w1", y: 0, h: 5 }), w({ id: "x", y: 5, h: 3 }));
  expect(nextId(base)).toBe("w2");
  const added = addWidget(base, CATALOG_BY_TYPE.my_todo);
  expect(added.widgets[2]).toEqual({ id: "w2", type: "my_todo", x: 0, y: 8, w: 6, h: 5, params: { limit: null } });
  expect(removeWidget(added, "w1").widgets.map((x) => x.id)).toEqual(["x", "w2"]);
  expect(setParams(added, "w2", { limit: 5 }).widgets[2].params).toEqual({ limit: 5 });
});

test("单列顺序按行再按列", () => {
  expect(stackOrder(L(w({ id: "c", y: 5, x: 0 }), w({ id: "b", y: 0, x: 6 }), w({ id: "a", y: 0, x: 0 }))).map((x) => x.id)).toEqual(["a", "b", "c"]);
});

test("条数超过该卡片上限时退回默认", () => {
  const out = normalize(
    L(
      w({ id: "a", type: "countries", params: { days: null, limit: 30 } }),
      w({ id: "b", type: "countries", params: { days: null, limit: 10 } }),
      w({ id: "c", type: "top", params: { category: null, limit: 50 } }),
    ),
    all,
  ).widgets;
  expect(out.map((x) => x.params.limit)).toEqual([null, 10, 50]);
  expect([CATALOG_BY_TYPE.by_category.maxLimit, CATALOG_BY_TYPE.by_source.maxLimit, CATALOG_BY_TYPE.networks.maxLimit]).toEqual([20, 15, 10]);
});

test("满 30 张时不再添加", () => {
  const full = L(...Array.from({ length: MAX_WIDGETS }, (_, i) => w({ id: `x${i}`, y: i * 5 })));
  expect(addWidget(full, CATALOG_BY_TYPE.mttd)).toBe(full);
});
