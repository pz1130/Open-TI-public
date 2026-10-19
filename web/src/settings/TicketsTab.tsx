import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Checkbox, Form, Input, Radio, Select, Space, Spin, Switch, Typography } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useConfig, useConfigSecrets, useMe, useTestTickets } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import { errorMessage } from "../api/client";
import type { SecretDraft } from "./alertingForm";
import ConfigShell from "./ConfigShell";
import SecretInput from "./SecretInput";
import { JiraCard, ServiceNowCard } from "./TicketRemoteCards";
import { fromForm, REMOTE_MODES, SEVERITIES, toForm } from "./ticketsForm";
import { useConfigSaver } from "./useConfigSaver";

const STATES = ["open", "acknowledged", "closed"];
type Json = Record<string, unknown>;

export default function TicketsTab() {
  const { t } = useTranslation();
  const me = useMe();
  const canWrite = can(me.data, "config:write");
  const query = useConfig("tickets");
  const alerting = useConfig("alerting");
  const secrets = useConfigSecrets("tickets", canWrite);
  const saver = useConfigSaver("tickets");
  const tester = useTestTickets();
  const [form] = Form.useForm<Json>();
  const [drafts, setDrafts] = useState<SecretDraft>({});
  const mode = Form.useWatch("mode", form);
  const remote = REMOTE_MODES.includes(mode as string);

  useEffect(() => {
    if (!query.data) return;
    form.setFieldsValue(toForm(query.data.data as Json) as Parameters<typeof form.setFieldsValue>[0]);
    setDrafts({});
    tester.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- tester 每次渲染都是新对象
  }, [query.data, form]);

  if (query.isPending) return <Spin />;
  if (query.isError) return <QueryError error={query.error} />;
  const config = query.data;
  const base = ((alerting.data?.data as Json | undefined)?.public_base_url as string | undefined) ?? "";
  const state = (name: string) => secrets.data?.secrets.find((item) => item.name === name);
  const keyMissing = secrets.data?.encryption_key === false;
  const setSecret = (name: string, value: string | null | undefined) =>
    setDrafts((current) => { const next = { ...current }; if (value === undefined) delete next[name]; else next[name] = value; return next; });
  const secretProps = { canWrite, keyMissing, state, drafts, setSecret };

  async function onSave(note: string | null) {
    await form.validateFields();
    // getFieldsValue(true)：包含未显示的段（切换方式时另一段与状态映射保留）
    const data = fromForm(form.getFieldsValue(true) as Json);
    const ok = await saver.submit({ data, note, base_version: config.version, ...(Object.keys(drafts).length ? { secrets: drafts } : {}) });
    if (ok) { setDrafts({}); tester.reset(); }
    return ok;
  }

  const result = tester.data;
  const resultError = tester.error ? errorMessage(tester.error) : result?.kind === "incomplete" ? t("settings.tickets.testIncomplete") : result?.detail;

  return <ConfigShell kind="tickets" config={config} canWrite={canWrite} saver={saver}
    onReload={() => { void query.refetch(); }} onSave={onSave}>
    <Form form={form} layout="vertical" disabled={!canWrite} className="oti-config-form">
      <Space wrap align="start">
        <Form.Item name="enabled" label={t("settings.tickets.enabled")} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="mode" label={t("settings.tickets.mode")}>
          <Radio.Group options={[{ value: "webhook", label: "Webhook" }, { value: "email", label: t("settings.tickets.email") },
            { value: "jira", label: "Jira Cloud" }, { value: "servicenow", label: "ServiceNow" }]} />
        </Form.Item>
        {mode === "webhook" && <Form.Item name="id_field" label={t("settings.tickets.idField")}><Input style={{ width: 180 }} /></Form.Item>}
      </Space>
      <Form.Item name="auto_push" label={t("settings.tickets.autoPush")} extra={t("settings.tickets.autoPushHint")}>
        <Checkbox.Group options={SEVERITIES.map((severity) => ({ value: severity, label: t(`severity.${severity}`) }))} />
      </Form.Item>
      {mode === "email" && <Form.Item name="email_to" label={t("settings.tickets.emailTo")}><Select mode="tags" open={false} tokenSeparators={[",", " ", ";"]} /></Form.Item>}
      {remote && <>
        <Form.Item name="include_accounts" label={t("settings.tickets.includeAccounts")} extra={t("settings.tickets.includeAccountsHint")} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="proxy" label={t("settings.tickets.proxy")} extra={t("settings.tickets.proxyHint")}><Input style={{ width: 300 }} /></Form.Item>
      </>}
      {mode === "jira" && <JiraCard {...secretProps} />}
      {mode === "servicenow" && <ServiceNowCard form={form} {...secretProps} />}
      {!remote && <Card size="small" title={t("settings.tickets.statusMap")}>
        <Form.List name="status_map">{(rows, ops) => <Space direction="vertical">
          {rows.map((row) => <Space key={row.key} align="start">
            <Form.Item name={[row.name, "status"]} rules={[{ required: true, whitespace: true, message: t("settings.required") }]}>
              <Input aria-label={t("settings.tickets.status")} placeholder={t("settings.tickets.status")} style={{ width: 180 }} />
            </Form.Item>
            <Form.Item name={[row.name, "state"]}><Select style={{ width: 160 }} options={STATES.map((value) => ({ value, label: t(`settings.tickets.state.${value}`) }))} /></Form.Item>
            {canWrite && <Button type="text" icon={<MinusCircleOutlined />} onClick={() => ops.remove(row.name)} />}
          </Space>)}
          {canWrite && <Button size="small" icon={<PlusOutlined />} aria-label={t("settings.tickets.addMapping")} onClick={() => ops.add({ status: "", state: "closed" })}>{t("settings.tickets.addMapping")}</Button>}
        </Space>}</Form.List>
      </Card>}
    </Form>
    {canWrite && mode === "webhook" && <Card size="small" title="Webhook"><Form layout="vertical">
      <Form.Item label={t("settings.tickets.webhookUrl")}>
        <SecretInput label={t("settings.tickets.webhookUrl")} state={state("webhook_url")} draft={drafts.webhook_url}
          onChange={(value) => setSecret("webhook_url", value)} disabled={!canWrite} keyMissing={keyMissing} />
      </Form.Item>
      <Form.Item label={t("settings.tickets.signingKey")} extra={t("settings.tickets.signingKeyHint")}>
        <SecretInput label={t("settings.tickets.signingKey")} state={state("signing_key")} draft={drafts.signing_key}
          onChange={(value) => setSecret("signing_key", value)} disabled={!canWrite} keyMissing={keyMissing} />
      </Form.Item>
    </Form></Card>}
    {canWrite && remote && <Space direction="vertical">
      <Space>
        <Button onClick={() => tester.mutate()} loading={tester.isPending}>{t("settings.tickets.test")}</Button>
        <Typography.Text type="secondary">{t("settings.tickets.testHint")}</Typography.Text>
      </Space>
      {(result || tester.error) && <Alert showIcon type={result?.ok ? "success" : "error"}
        message={result?.ok ? t("settings.tickets.testOk") : t("settings.tickets.testFailed", { error: resultError })} />}
    </Space>}
    {mode === "webhook" && <>
      <Typography.Text type="secondary">{t("settings.tickets.callback")}</Typography.Text>
      <Typography.Text code copyable>{`${base}/api/v1/integrations/tickets`}</Typography.Text>
    </>}
  </ConfigShell>;
}
