import type { TFunction } from "i18next";

/** 活动名为空时用"最早出现的域名 等 N 个"作默认名，随界面语言渲染。 */
export function campaignLabel(t: TFunction, c: { name?: string | null; label_value: string; member_count: number }): string {
  return c.name || t("campaigns.defaultName", { value: c.label_value, count: c.member_count });
}
