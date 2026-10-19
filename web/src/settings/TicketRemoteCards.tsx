import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";
import { Button, Card, Form, Input, Radio, Select, Space, Typography } from "antd";
import type { FormInstance, FormRule } from "antd";
import { useTranslation } from "react-i18next";
import type { SecretState } from "../api/hooks";
import SecretInput from "./SecretInput";
import { SEVERITIES } from "./ticketsForm";

type SecretProps = {
  canWrite: boolean;
  keyMissing: boolean;
  state: (name: string) => SecretState | undefined;
  drafts: Record<string, string | null | undefined>;
  setSecret: (name: string, value: string | null | undefined) => void;
};

function Secret({ name, label, p }: { name: string; label: string; p: SecretProps }) {
  return <Form.Item label={label}>
    <SecretInput label={label} state={p.state(name)} draft={p.drafts[name]}
      onChange={(value) => p.setSecret(name, value)} disabled={!p.canWrite} keyMissing={p.keyMissing} />
  </Form.Item>;
}

function ExtraFields({ name, canWrite }: { name: string; canWrite: boolean }) {
  const { t } = useTranslation();
  return <Form.Item label={t("settings.tickets.extraFields")} extra={t("settings.tickets.extraHint")}>
    <Form.List name={name}>{(rows, ops) => <Space direction="vertical">
      {rows.map((row) => <Space key={row.key} align="start">
        <Form.Item name={[row.name, "key"]} rules={[{ required: true, whitespace: true, message: t("settings.required") }]}>
          <Input aria-label={t("settings.tickets.extraKey")} placeholder={t("settings.tickets.extraKey")} style={{ width: 200 }} />
        </Form.Item>
        <Form.Item name={[row.name, "value"]}>
          <Input aria-label={t("settings.tickets.extraValue")} placeholder={t("settings.tickets.extraValue")} style={{ width: 280 }} />
        </Form.Item>
        {canWrite && <Button type="text" icon={<MinusCircleOutlined />} onClick={() => ops.remove(row.name)} />}
      </Space>)}
      {canWrite && <Button size="small" icon={<PlusOutlined />} aria-label={t("settings.tickets.addField")} onClick={() => ops.add({ key: "", value: "" })}>{t("settings.tickets.addField")}</Button>}
    </Space>}</Form.List>
  </Form.Item>;
}

export function JiraCard(p: SecretProps) {
  const { t } = useTranslation();
  return <Card size="small" title="Jira Cloud">
    <Space wrap align="start">
      <Form.Item name={["jira", "base_url"]} label={t("settings.tickets.jiraSite")} rules={[{ required: true, message: t("settings.required") }]}>
        <Input placeholder="https://example.atlassian.net" style={{ width: 300 }} />
      </Form.Item>
      <Form.Item name={["jira", "email"]} label={t("settings.tickets.jiraEmail")} rules={[{ required: true, message: t("settings.required") }]}>
        <Input style={{ width: 240 }} />
      </Form.Item>
      <Form.Item name={["jira", "project_key"]} label={t("settings.tickets.projectKey")} rules={[{ required: true, message: t("settings.required") }]}>
        <Input placeholder="SEC" style={{ width: 120 }} />
      </Form.Item>
      <Form.Item name={["jira", "issue_type"]} label={t("settings.tickets.issueType")}>
        <Input style={{ width: 160 }} />
      </Form.Item>
    </Space>
    {p.canWrite && <Secret name="jira_api_token" label={t("settings.tickets.apiToken")} p={p} />}
    <Form.Item label={t("settings.tickets.priorityMap")}>
      <Space wrap>{SEVERITIES.map((severity) => <Form.Item key={severity} name={["jira", "priority_map", severity]} noStyle>
        <Input addonBefore={t(`severity.${severity}`)} aria-label={t("settings.tickets.priorityFor", { severity: t(`severity.${severity}`) })} style={{ width: 200 }} />
      </Form.Item>)}</Space>
    </Form.Item>
    <ExtraFields name="jira_extra" canWrite={p.canWrite} />
  </Card>;
}

export function ServiceNowCard({ form, ...p }: SecretProps & { form: FormInstance }) {
  const { t } = useTranslation();
  const auth = Form.useWatch(["servicenow", "auth"], form) ?? "basic";
  const levels = [1, 2, 3].map((value) => ({ value, label: String(value) }));
  const pair = (severity: string, field: "urgency" | "impact"): FormRule => ({ getFieldValue }) => ({
    validator(_: unknown, value: unknown) {
      const other = getFieldValue(["servicenow", "urgency_impact_map", severity, field === "urgency" ? "impact" : "urgency"]);
      return (value == null) === (other == null) ? Promise.resolve() : Promise.reject(new Error(t("settings.tickets.pairRequired")));
    },
  });
  return <Card size="small" title="ServiceNow">
    <Space wrap align="start">
      <Form.Item name={["servicenow", "base_url"]} label={t("settings.tickets.snInstance")} rules={[{ required: true, message: t("settings.required") }]}>
        <Input placeholder="https://example.service-now.com" style={{ width: 300 }} />
      </Form.Item>
      <Form.Item name={["servicenow", "table"]} label={t("settings.tickets.table")} extra={t("settings.tickets.tableHint")}>
        <Input style={{ width: 200 }} />
      </Form.Item>
      <Form.Item name={["servicenow", "auth"]} label={t("settings.tickets.auth")}>
        <Radio.Group options={[{ value: "basic", label: "Basic" }, { value: "oauth", label: "OAuth" }]} />
      </Form.Item>
    </Space>
    {auth === "basic"
      ? <Form.Item name={["servicenow", "username"]} label={t("settings.tickets.username")} rules={[{ required: true, message: t("settings.required") }]}><Input style={{ width: 240 }} /></Form.Item>
      : <Form.Item name={["servicenow", "client_id"]} label="client_id" rules={[{ required: true, message: t("settings.required") }]}><Input style={{ width: 300 }} /></Form.Item>}
    {p.canWrite && (auth === "basic"
      ? <Secret name="servicenow_password" label={t("settings.tickets.password")} p={p} />
      : <Secret name="servicenow_client_secret" label="client_secret" p={p} />)}
    <Form.Item label={t("settings.tickets.urgencyImpact")}>
      <Space direction="vertical">{SEVERITIES.map((severity) => <Space key={severity} align="start">
        <Typography.Text style={{ display: "inline-block", width: 48 }}>{t(`severity.${severity}`)}</Typography.Text>
        <Form.Item name={["servicenow", "urgency_impact_map", severity, "urgency"]} dependencies={[["servicenow", "urgency_impact_map", severity, "impact"]]} rules={[pair(severity, "urgency")]}>
          <Select allowClear placeholder={t("settings.tickets.urgency")} aria-label={`${t(`severity.${severity}`)} ${t("settings.tickets.urgency")}`} options={levels} style={{ width: 120 }} />
        </Form.Item>
        <Form.Item name={["servicenow", "urgency_impact_map", severity, "impact"]} dependencies={[["servicenow", "urgency_impact_map", severity, "urgency"]]} rules={[pair(severity, "impact")]}>
          <Select allowClear placeholder={t("settings.tickets.impact")} aria-label={`${t(`severity.${severity}`)} ${t("settings.tickets.impact")}`} options={levels} style={{ width: 120 }} />
        </Form.Item>
      </Space>)}</Space>
    </Form.Item>
    <ExtraFields name="servicenow_extra" canWrite={p.canWrite} />
  </Card>;
}
