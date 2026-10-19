import enUS from "./en-US.json";
import zhCN from "./zh-CN.json";

function flatten(obj: Record<string, unknown>, prefix = ""): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    v !== null && typeof v === "object" ? flatten(v as Record<string, unknown>, `${prefix}${k}.`) : [`${prefix}${k}`],
  );
}

test("中英文案的键完全一致", () => {
  expect(flatten(enUS).sort()).toEqual(flatten(zhCN).sort());
});

test("没有空文案", () => {
  for (const [name, dict] of [["zh-CN", zhCN], ["en-US", enUS]] as const) {
    const empty = flatten(dict).filter((k) => {
      const v = k.split(".").reduce<unknown>((o, p) => (o as Record<string, unknown>)[p], dict);
      return typeof v !== "string" || v.trim() === "";
    });
    expect(empty, name).toEqual([]);
  }
});
