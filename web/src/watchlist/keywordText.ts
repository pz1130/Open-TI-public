import type { TFunction } from "i18next";
import type { KeywordChange, KeywordKind } from "../api/hooks";
import { ApiError, errorMessage, type Schemas } from "../api/client";
import { fmtTime } from "../components/format";

export const CONNECTOR_NAMES: Record<string, string> = { crtsh: "crt.sh", dnstwist: "dnstwist" };

export function backfillLines(t: TFunction, backfill: Record<string, Schemas["BackfillOut"]>): string[] {
  return Object.entries(backfill).map(([id, r]) =>
    t(`watchlist.keywords.backfill.${r.status}`, {
      name: CONNECTOR_NAMES[id] ?? id,
      time: fmtTime(r.next_allowed_at),
      reason: r.reason ?? "",
    }),
  );
}

/** 保存后的提示：新版本号 + 每个连接器的回溯结果。 */
export function changeMessage(t: TFunction, change: KeywordChange): string {
  if (!change.changed) return t("watchlist.keywords.unchanged");
  return [t("watchlist.keywords.saved", { version: change.version }), ...backfillLines(t, change.backfill)].join("；");
}

/** 在规则数据上加入一个词，生成试跑用的草稿（服务器会再做规范化与校验）。 */
export function draftRules(
  data: Record<string, unknown>, kind: KeywordKind, value: string, affixes: string[],
): Record<string, unknown> {
  const domains = { ...(data.domains as Record<string, unknown>) };
  const v = value.trim().toLowerCase();
  const list = (field: string) => [...((domains[field] as string[] | undefined) ?? [])];
  if (kind === "brand") domains.brand_tokens = [...list("brand_tokens"), v];
  if (kind === "official") domains.official = [...list("official"), v];
  if (kind === "lookalike") domains.known_lookalikes = [...list("known_lookalikes"), v];
  if (kind === "restricted") {
    domains.restricted_tokens = { ...(domains.restricted_tokens as Record<string, string[]>), [v]: affixes };
  }
  return { ...data, domains };
}

/** Translate structured keyword API errors without hiding unexpected failures. */
export function keywordError(t: TFunction, error: unknown): string {
  if (error instanceof ApiError) {
    const detail = (error.detail as { detail?: { reason?: unknown } } | undefined)?.detail;
    if (typeof detail?.reason === "string") {
      return t(`watchlist.keywords.errors.${detail.reason}`, { defaultValue: errorMessage(error) });
    }
  }
  return errorMessage(error);
}
