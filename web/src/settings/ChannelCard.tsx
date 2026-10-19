import { MinusCircleOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Checkbox, Form, Input, Select, Space, Switch } from "antd";
import { useTranslation } from "react-i18next";
import type { AlertingTestResult, SecretState } from "../api/hooks";
import { CATEGORIES } from "../dashboard/catalog";
import { secretName, slugify, type SecretDraft } from "./alertingForm";
import SecretInput from "./SecretInput";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const REPORTS = ["daily", "weekly", "monthly"];
const TAGS = { mode: "tags" as const, open: false, tokenSeparators: [",", " ", ";", "\n"] };

type Props = {
  field: { key: number; name: number };
  locked: boolean; // 已保存的渠道：ID 只读
  disabled: boolean;
  keyMissing: boolean;
  secrets: SecretState[] | undefined;
  drafts: SecretDraft;
  onSecret: (name: string, v: string | null | undefined) => void;
  onSecretMove: (prevId: string, nextId: string) => void;
  onRemove: () => void;
  onTest: () => void;
  testing: boolean;
  testResult: AlertingTestResult | undefined;
};

export default function ChannelCard({ field, locked, disabled, keyMissing, secrets, drafts, onSecret, onSecretMove, onRemove, onTest, testing, testResult }: Props) {
  const { t } = useTranslation();
  const form = Form.useFormInstance();
  const type = Form.useWatch(["channels", field.name, "type"], form) as "teams" | "email";
  const id = Form.useWatch(["channels", field.name, "id"], form) as string | undefined;
  const hook = id ? secretName(id) : "";
  return (
    <Card
      size="small"
      title={t(`settings.alerting.type.${type ?? "teams"}`)}
      extra={!disabled && <Button type="text" danger icon={<MinusCircleOutlined />} aria-label={t("settings.alerting.removeChannel")} onClick={onRemove} />}
    >
      <Space wrap align="start">
        <Form.Item name={[field.name, "name"]} label={t("settings.alerting.name")} rules={[{ required: true, message: t("settings.required") }]}>
          <Input
            style={{ width: 200 }}
            onChange={(e) => {
              if (locked) return;
              const next = slugify(e.target.value, `${type ?? "teams"}-${field.name + 1}`);
              const prev = id ?? "";
              if (prev === next) return;
              form.setFieldValue(["channels", field.name, "id"], next);
              onSecretMove(prev, next);
            }}
          />
        </Form.Item>
        <Form.Item name={[field.name, "id"]} label={t("settings.alerting.id")} rules={[{ required: true, pattern: /^[a-z0-9][a-z0-9-]{0,31}$/, message: t("settings.alerting.idRule") }]}>
          <Input
            style={{ width: 180 }}
            disabled={disabled || locked}
            onChange={(e) => {
              if (locked) return;
              const next = e.target.value;
              const prev = id ?? "";
              if (prev !== next) onSecretMove(prev, next);
            }}
          />
        </Form.Item>
        <Form.Item name={[field.name, "type"]} hidden><Input /></Form.Item>
        <Form.Item name={[field.name, "enabled"]} label={t("settings.alerting.enabled")} valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name={[field.name, "notices"]} label={t("settings.alerting.notices")} valuePropName="checked">
          <Switch />
        </Form.Item>
      </Space>
      <Form.Item name={[field.name, "severities"]} label={t("settings.alerting.severities")}>
        <Checkbox.Group options={SEVERITIES.map((s) => ({ value: s, label: t(`severity.${s}`) }))} />
      </Form.Item>
      <Form.Item name={[field.name, "categories"]} label={t("settings.alerting.categories")} extra={t("settings.alerting.categoriesHint")}>
        <Select mode="multiple" allowClear options={CATEGORIES.map((c) => ({ value: c, label: t(`category.${c}`) }))} />
      </Form.Item>
      <Form.Item name={[field.name, "reports"]} label={t("settings.alerting.reports")}>
        <Checkbox.Group options={REPORTS.map((r) => ({ value: r, label: t(`settings.alerting.report.${r}`) }))} />
      </Form.Item>
      {type === "email" ? (
        <Form.Item name={[field.name, "recipients"]} label={t("settings.alerting.recipients")}>
          <Select {...TAGS} />
        </Form.Item>
      ) : (
        !disabled && (
          <Form.Item label={t("settings.alerting.webhook")}>
            <SecretInput
              label={t("settings.alerting.webhook")}
              state={secrets?.find((s) => s.name === hook)}
              draft={drafts[hook]}
              onChange={(v) => hook && onSecret(hook, v)}
              disabled={disabled || !id}
              keyMissing={keyMissing}
            />
          </Form.Item>
        )
      )}
      {!disabled && (
        <Space direction="vertical" style={{ width: "100%" }}>
          <Button onClick={onTest} loading={testing}>{t("settings.alerting.test")}</Button>
          {testResult && (
            <Alert
              type={testResult.ok ? "success" : "error"}
              showIcon
              message={testResult.ok ? t("settings.alerting.testOk") : t("settings.alerting.testFailed", { error: testResult.error })}
            />
          )}
        </Space>
      )}
    </Card>
  );
}
