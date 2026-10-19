import { fromForm, toForm } from "./rulesForm";

const DATA = {
  project: "sample-brand-protection",
  authorization_ref: "SBR-1",
  languages: ["en", "zh"],
  sets: {
    brand: {
      weight: 1, role: "match", type: "brand", approval_ref: null, category: null, private: false,
      terms: [
        { value: "Sample Brand", mode: "phrase", case_sensitive: false, remote_search: true, variants: null, require_any_within: null },
        { value: "SBR", mode: "token", case_sensitive: true, remote_search: false, variants: null,
          require_any_within: { window_chars: 40, terms: ["bank", "loan"] } },
      ],
    },
  },
  domains: {
    official: ["sbr.int"], known_lookalikes: [], brand_tokens: ["sbr"], combo_affixes: ["login"],
    fraud_affixes: [], restricted_tokens: { orbit: ["fund"] }, short_token_max_len: 4,
  },
};

test("表单值与接口数据互转不丢字段", () => {
  const form = toForm(DATA);
  expect(form.sets[0].name).toBe("brand");
  expect(form.sets[0].terms[1]).toMatchObject({ ctx_window: 40, ctx_terms: ["bank", "loan"] });
  expect(form.domains.restricted).toEqual([{ token: "orbit", affixes: ["fund"] }]);
  expect(fromForm(form)).toEqual(DATA);
});

test("空的上下文约束与审批编号转成 null", () => {
  const form = toForm(DATA);
  form.sets[0].terms[1].ctx_terms = [];
  form.sets[0].approval_ref = "  ";
  const out = fromForm(form) as typeof DATA;
  expect(out.sets.brand.terms[1].require_any_within).toBeNull();
  expect(out.sets.brand.approval_ref).toBeNull();
});
