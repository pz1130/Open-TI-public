/** 关键词规则：接口数据（ProjectRules 的 JSON）与 antd 表单值互转。集合与受限词在表单中是数组。 */

type Json = Record<string, unknown>;

export type TermForm = {
  value: string;
  mode: "phrase" | "token";
  case_sensitive: boolean;
  remote_search: boolean;
  variants: string | null;
  ctx_window: number | null;
  ctx_terms: string[];
};

export type SetForm = {
  name: string;
  weight: number;
  role: "match" | "booster" | "negative";
  type: "brand" | "executive" | "product" | "supplier" | "other";
  approval_ref: string | null;
  category: "fraud_scam" | "negative_press" | null;
  private: boolean;
  terms: TermForm[];
};

export type RulesFormValues = {
  project: string;
  authorization_ref: string;
  languages: string[];
  sets: SetForm[];
  domains: {
    official: string[];
    known_lookalikes: string[];
    brand_tokens: string[];
    combo_affixes: string[];
    fraud_affixes: string[];
    restricted: { token: string; affixes: string[] }[];
    short_token_max_len: number;
  };
};

const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);
const blankToNull = (v: string | null | undefined): string | null => (v && v.trim() ? v.trim() : null);

export const EMPTY_TERM: TermForm = {
  value: "", mode: "phrase", case_sensitive: false, remote_search: true, variants: null, ctx_window: null, ctx_terms: [],
};

export function toForm(data: Json): RulesFormValues {
  const sets = (data.sets ?? {}) as Record<string, Json>;
  const domains = (data.domains ?? {}) as Json;
  return {
    project: String(data.project ?? ""),
    authorization_ref: String(data.authorization_ref ?? ""),
    languages: list(data.languages),
    sets: Object.entries(sets).map(([name, s]) => ({
      name,
      weight: Number(s.weight ?? 1),
      role: (s.role ?? "match") as SetForm["role"],
      type: (s.type ?? "brand") as SetForm["type"],
      approval_ref: (s.approval_ref as string | null) ?? null,
      category: (s.category as SetForm["category"]) ?? null,
      private: Boolean(s.private),
      terms: ((s.terms ?? []) as Json[]).map((t) => {
        const ctx = t.require_any_within as { window_chars: number; terms: string[] } | null | undefined;
        return {
          value: String(t.value ?? ""),
          mode: (t.mode ?? "phrase") as TermForm["mode"],
          case_sensitive: Boolean(t.case_sensitive),
          remote_search: t.remote_search === undefined ? true : Boolean(t.remote_search),
          variants: (t.variants as string | null) ?? null,
          ctx_window: ctx ? ctx.window_chars : null,
          ctx_terms: ctx ? list(ctx.terms) : [],
        };
      }),
    })),
    domains: {
      official: list(domains.official),
      known_lookalikes: list(domains.known_lookalikes),
      brand_tokens: list(domains.brand_tokens),
      combo_affixes: list(domains.combo_affixes),
      fraud_affixes: list(domains.fraud_affixes),
      restricted: Object.entries((domains.restricted_tokens ?? {}) as Record<string, string[]>).map(([token, affixes]) => ({
        token, affixes: list(affixes),
      })),
      short_token_max_len: Number(domains.short_token_max_len ?? 4),
    },
  };
}

export function fromForm(v: RulesFormValues): Json {
  return {
    project: v.project.trim(),
    authorization_ref: v.authorization_ref.trim(),
    languages: v.languages ?? [],
    sets: Object.fromEntries(
      (v.sets ?? []).map((s) => [
        s.name.trim(),
        {
          weight: s.weight,
          role: s.role,
          type: s.type,
          approval_ref: blankToNull(s.approval_ref),
          category: s.category ?? null,
          private: Boolean(s.private),
          terms: (s.terms ?? []).map((t) => ({
            value: t.value,
            mode: t.mode,
            case_sensitive: Boolean(t.case_sensitive),
            remote_search: Boolean(t.remote_search),
            variants: t.variants ?? null,
            require_any_within:
              t.ctx_window && (t.ctx_terms ?? []).length ? { window_chars: t.ctx_window, terms: t.ctx_terms } : null,
          })),
        },
      ]),
    ),
    domains: {
      official: v.domains.official ?? [],
      known_lookalikes: v.domains.known_lookalikes ?? [],
      brand_tokens: v.domains.brand_tokens ?? [],
      combo_affixes: v.domains.combo_affixes ?? [],
      fraud_affixes: v.domains.fraud_affixes ?? [],
      restricted_tokens: Object.fromEntries((v.domains.restricted ?? []).map((r) => [r.token.trim(), r.affixes ?? []])),
      short_token_max_len: v.domains.short_token_max_len,
    },
  };
}
