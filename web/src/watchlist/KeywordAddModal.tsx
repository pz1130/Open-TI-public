import { Alert, App, Button, Form, Input, Modal, Select, Space, Table, Tag, Typography } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../api/client";
import { useAddKeyword, useConfig, useRulesTest, useValidateConfig, type KeywordKind } from "../api/hooks";
import { listPagination } from "../components/pagination";
import { changeMessage, draftRules, keywordError } from "./keywordText";

type Values = { kind: KeywordKind; value: string; affixes?: string[] };
type Report = Schemas["DomainReportOut"];
const KINDS: KeywordKind[] = ["brand", "restricted", "official", "lookalike"];

export default function KeywordAddModal({ open, initialKind, shortMax, canTest, onClose }: {
  open: boolean; initialKind: KeywordKind; shortMax: number; canTest: boolean; onClose: () => void;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<Values>();
  useEffect(() => {
    if (open) {
      form.resetFields();
      form.setFieldsValue({ kind: initialKind, value: "", affixes: [] });
    }
  }, [open, initialKind, form]);
  const kind = Form.useWatch("kind", form) ?? initialKind;
  const value = Form.useWatch("value", form) ?? "";
  const [samples, setSamples] = useState("");
  const [testError, setTestError] = useState<string | null>(null);
  const add = useAddKeyword();
  const rules = useConfig("rules", open && canTest);
  const validate = useValidateConfig("rules");
  const test = useRulesTest();
  const isToken = kind === "brand" || kind === "restricted";
  const short = isToken && value.trim().length > 0 && value.trim().length <= shortMax;

  const close = () => { form.resetFields(); setSamples(""); setTestError(null); test.reset(); onClose(); };

  const runTest = async () => {
    setTestError(null);
    const v = form.getFieldsValue();
    const domains = samples.split("\n").map((s) => s.trim()).filter(Boolean).slice(0, 200);
    if (!rules.data || !v.value?.trim() || domains.length === 0) return;
    try {
      const draft = draftRules(rules.data.data as Record<string, unknown>, v.kind ?? initialKind, v.value, v.affixes ?? []);
      const checked = await validate.mutateAsync({ data: draft });
      if (!checked.ok || !checked.yaml) {
        setTestError(checked.errors?.map((e) => e.message).join("；") ?? t("watchlist.keywords.testInvalid"));
        return;
      }
      await test.mutateAsync({ draft_yaml: checked.yaml, domains, text: "" });
    } catch (e) {
      setTestError(keywordError(t, e));
    }
  };

  return (
    <Modal open={open} title={t("watchlist.keywords.add")} footer={null} onCancel={close} destroyOnHidden width={640}>
      <Form<Values> form={form} name="keyword-add" layout="vertical" initialValues={{ kind: initialKind, affixes: [] }}
        onFinish={(v) => add.mutate({ kind: v.kind, value: v.value, affixes: v.kind === "restricted" ? v.affixes ?? [] : [] }, {
          onSuccess: (r) => { void message.success(changeMessage(t, r)); close(); },
          onError: (e) => void message.error(t("common.error", { message: keywordError(t, e) })),
        })}>
        <Form.Item name="kind" label={t("watchlist.keywords.kind")}>
          <Select options={KINDS.map((k) => ({ value: k, label: t(`watchlist.keywords.kinds.${k}`) }))} />
        </Form.Item>
        <Form.Item name="value" label={t("watchlist.keywords.value")} rules={[{ required: true, whitespace: true }]}
          extra={isToken ? t("watchlist.keywords.tokenHint") : t("watchlist.keywords.domainHint")}>
          <Input maxLength={253} />
        </Form.Item>
        {short && <Alert type="info" showIcon style={{ marginBottom: 16 }} message={t("watchlist.keywords.shortHint", { max: shortMax })} />}
        {kind === "restricted" && (
          <Form.Item name="affixes" label={t("watchlist.keywords.affixes")} rules={[{ required: true, type: "array", min: 1 }]}>
            <Select mode="tags" tokenSeparators={[",", " "]} open={false} aria-label={t("watchlist.keywords.affixes")} />
          </Form.Item>
        )}
        {canTest && (
          <Space direction="vertical" style={{ width: "100%", marginBottom: 16 }}>
            <Typography.Text strong>{t("watchlist.keywords.test")}</Typography.Text>
            <Input.TextArea rows={3} value={samples} onChange={(e) => setSamples(e.target.value)}
              placeholder={t("watchlist.keywords.testPlaceholder")} aria-label={t("watchlist.keywords.test")} />
            <Button onClick={() => void runTest()} loading={validate.isPending || test.isPending}
              disabled={!rules.data}>{t("watchlist.keywords.runTest")}</Button>
            {testError && <Alert type="error" showIcon message={testError} />}
            {test.data && (
              <Table<Report> rowKey="input" size="small" pagination={listPagination} dataSource={test.data.domains}
                columns={[
                  { title: t("watchlist.domain"), dataIndex: "input" },
                  { title: t("watchlist.keywords.testResult"), dataIndex: "status",
                    render: (s: string) => <Tag color={s === "match" ? "red" : undefined}>{t(`watchlist.keywords.testStatus.${s}`, { defaultValue: s })}</Tag> },
                  { title: t("watchlist.keywords.testReasons"), key: "reasons",
                    render: (_, r) => (r.reasons ?? []).map((x) => `${String(x.reason)}:${String(x.token ?? "")}`).join(", ") || "–" },
                ]} />
            )}
          </Space>
        )}
        <Button type="primary" htmlType="submit" loading={add.isPending}>{t("common.submit")}</Button>
      </Form>
    </Modal>
  );
}
