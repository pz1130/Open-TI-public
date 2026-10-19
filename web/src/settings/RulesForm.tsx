import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";
import { Button, Card, Form, Input, InputNumber, Select, Space, Switch } from "antd";
import { useTranslation } from "react-i18next";
import { EMPTY_TERM, type RulesFormValues } from "./rulesForm";

const TAGS = { mode: "tags" as const, open: false, tokenSeparators: [",", " ", "\n"] };
const DOMAIN_LISTS = ["official", "known_lookalikes", "brand_tokens", "combo_affixes", "fraud_affixes"] as const;

export default function RulesForm({ disabled, canSwitchProject = false }: { disabled: boolean; canSwitchProject?: boolean }) {
  const { t } = useTranslation();
  const form = Form.useFormInstance<RulesFormValues>();
  const uniqueName = {
    validator: async (_: unknown, value: string) => {
      const names = (form.getFieldValue("sets") as { name: string }[] | undefined)?.map((s) => s?.name?.trim()) ?? [];
      if (value && names.filter((n) => n === value.trim()).length > 1) throw new Error(t("settings.rules.duplicateSet"));
    },
  };
  return (
    <>
      <Card size="small" title={t("settings.rules.basic")}>
        <Space wrap align="start">
          <Form.Item name="project" label={t("settings.rules.project")} extra={t("settings.projects.projectHint")} rules={[{ required: true, message: t("settings.required") }]}>
            <Input readOnly={!canSwitchProject} style={{ width: 260 }} />
          </Form.Item>
          <Form.Item name="authorization_ref" label={t("settings.rules.authorizationRef")} rules={[{ required: true, message: t("settings.required") }]}>
            <Input style={{ width: 260 }} />
          </Form.Item>
          <Form.Item name="languages" label={t("settings.rules.languages")}>
            <Select {...TAGS} style={{ minWidth: 160 }} options={[{ value: "en" }, { value: "zh" }]} />
          </Form.Item>
        </Space>
      </Card>

      <Form.List name="sets">
        {(sets, { add, remove }) => (
          <>
            {sets.map((set) => (
              <Card
                key={set.key}
                size="small"
                title={<Form.Item noStyle shouldUpdate>{() => form.getFieldValue(["sets", set.name, "name"]) || t("settings.rules.newSet")}</Form.Item>}
                extra={!disabled && <Button type="text" danger icon={<MinusCircleOutlined />} aria-label={t("settings.rules.removeSet")} onClick={() => remove(set.name)} />}
              >
                <Space wrap align="start">
                  <Form.Item name={[set.name, "name"]} label={t("settings.rules.setName")} rules={[{ required: true, message: t("settings.required") }, uniqueName]}>
                    <Input style={{ width: 160 }} />
                  </Form.Item>
                  <Form.Item name={[set.name, "role"]} label={t("settings.rules.role")}>
                    <Select style={{ width: 120 }} options={["match", "booster", "negative"].map((v) => ({ value: v, label: t(`settings.rules.roles.${v}`) }))} />
                  </Form.Item>
                  <Form.Item name={[set.name, "type"]} label={t("settings.rules.type")}>
                    <Select style={{ width: 120 }} options={["brand", "executive", "product", "supplier", "other"].map((v) => ({ value: v, label: t(`settings.rules.types.${v}`) }))} />
                  </Form.Item>
                  <Form.Item name={[set.name, "weight"]} label={t("settings.rules.weight")}>
                    <InputNumber min={0} max={1} step={0.1} />
                  </Form.Item>
                  <Form.Item name={[set.name, "category"]} label={t("settings.rules.category")}>
                    <Select allowClear style={{ width: 140 }} options={["fraud_scam", "negative_press"].map((v) => ({ value: v, label: t(`settings.rules.categories.${v}`) }))} />
                  </Form.Item>
                  <Form.Item name={[set.name, "approval_ref"]} label={t("settings.rules.approvalRef")}>
                    <Input style={{ width: 180 }} />
                  </Form.Item>
                  <Form.Item name={[set.name, "private"]} label={t("settings.rules.private")} valuePropName="checked">
                    <Switch />
                  </Form.Item>
                </Space>
                <Form.List name={[set.name, "terms"]}>
                  {(terms, termOps) => (
                    <>
                      {terms.map((term) => (
                        <Space key={term.key} wrap align="start" className="oti-config-term">
                          <Form.Item name={[term.name, "value"]} rules={[{ required: true, message: t("settings.required") }]}>
                            <Input placeholder={t("settings.rules.term")} aria-label={t("settings.rules.term")} style={{ width: 220 }} />
                          </Form.Item>
                          <Form.Item name={[term.name, "mode"]}>
                            <Select style={{ width: 100 }} options={["phrase", "token"].map((v) => ({ value: v, label: t(`settings.rules.modes.${v}`) }))} />
                          </Form.Item>
                          <Form.Item name={[term.name, "case_sensitive"]} valuePropName="checked" label={t("settings.rules.caseSensitive")}>
                            <Switch size="small" />
                          </Form.Item>
                          <Form.Item name={[term.name, "remote_search"]} valuePropName="checked" label={t("settings.rules.remoteSearch")}>
                            <Switch size="small" />
                          </Form.Item>
                          <Form.Item name={[term.name, "ctx_window"]} label={t("settings.rules.ctxWindow")}>
                            <InputNumber min={1} max={2000} style={{ width: 90 }} />
                          </Form.Item>
                          <Form.Item name={[term.name, "ctx_terms"]} label={t("settings.rules.ctxTerms")}>
                            <Select {...TAGS} style={{ minWidth: 180 }} />
                          </Form.Item>
                          {!disabled && <Button type="text" icon={<MinusCircleOutlined />} aria-label={t("settings.rules.removeTerm")} onClick={() => termOps.remove(term.name)} />}
                        </Space>
                      ))}
                      {!disabled && <Button size="small" icon={<PlusOutlined />} onClick={() => termOps.add({ ...EMPTY_TERM })}>{t("settings.rules.addTerm")}</Button>}
                    </>
                  )}
                </Form.List>
              </Card>
            ))}
            {!disabled && (
              <Button icon={<PlusOutlined />} onClick={() => add({ name: "", weight: 1, role: "match", type: "brand", approval_ref: null, category: null, private: false, terms: [{ ...EMPTY_TERM }] })}>
                {t("settings.rules.addSet")}
              </Button>
            )}
          </>
        )}
      </Form.List>

      <Card size="small" title={t("settings.rules.domains")}>
        {DOMAIN_LISTS.map((f) => (
          <Form.Item key={f} name={["domains", f]} label={t(`settings.rules.domain.${f}`)} rules={f === "official" || f === "brand_tokens" ? [{ required: true, message: t("settings.required") }] : []}>
            <Select {...TAGS} />
          </Form.Item>
        ))}
        <Form.List name={["domains", "restricted"]}>
          {(rows, ops) => (
            <Form.Item label={t("settings.rules.domain.restricted")}>
              {rows.map((row) => (
                <Space key={row.key} align="start">
                  <Form.Item name={[row.name, "token"]} rules={[{ required: true, message: t("settings.required") }]}>
                    <Input placeholder={t("settings.rules.domain.restrictedToken")} style={{ width: 140 }} />
                  </Form.Item>
                  <Form.Item name={[row.name, "affixes"]} rules={[{ required: true, message: t("settings.required") }]}>
                    <Select {...TAGS} placeholder={t("settings.rules.domain.restrictedAffixes")} style={{ minWidth: 240 }} />
                  </Form.Item>
                  {!disabled && <Button type="text" icon={<MinusCircleOutlined />} onClick={() => ops.remove(row.name)} />}
                </Space>
              ))}
              {!disabled && <Button size="small" icon={<PlusOutlined />} onClick={() => ops.add({ token: "", affixes: [] })}>{t("settings.rules.domain.addRestricted")}</Button>}
            </Form.Item>
          )}
        </Form.List>
        <Form.Item name={["domains", "short_token_max_len"]} label={t("settings.rules.domain.shortTokenMaxLen")}>
          <InputNumber min={1} max={10} />
        </Form.Item>
      </Card>
    </>
  );
}
