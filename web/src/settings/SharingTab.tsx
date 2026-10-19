import { Alert, Button, Card, Form, Input, InputNumber, Select, Space, Spin, Switch } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage } from "../api/client";
import { useConfig, useConfigSecrets, useMe, useTestSharing, type AlertingTestResult } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import { CATEGORIES } from "../dashboard/catalog";
import type { SecretDraft } from "./alertingForm";
import ConfigShell from "./ConfigShell";
import SecretInput from "./SecretInput";
import { useConfigSaver } from "./useConfigSaver";

type Json = Record<string, unknown>;
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default function SharingTab() {
  const { t } = useTranslation();
  const me = useMe();
  const canWrite = can(me.data, "config:write");
  const query = useConfig("sharing");
  const secrets = useConfigSecrets("sharing", canWrite);
  const saver = useConfigSaver("sharing");
  const tester = useTestSharing();
  const [form] = Form.useForm<Json>();
  const [drafts, setDrafts] = useState<SecretDraft>({});
  const [results, setResults] = useState<Record<string, AlertingTestResult>>({});
  useEffect(() => { if (query.data) { form.setFieldsValue(query.data.data as Parameters<typeof form.setFieldsValue>[0]); setDrafts({}); } }, [query.data, form]);
  if (query.isPending) return <Spin />;
  if (query.isError) return <QueryError error={query.error} />;
  const config = query.data;
  const keyMissing = secrets.data?.encryption_key === false;
  const state = (name: string) => secrets.data?.secrets.find((item) => item.name === name);
  const setSecret = (name: string, value: string | null | undefined) =>
    setDrafts((current) => { const next = { ...current }; if (value === undefined) delete next[name]; else next[name] = value; return next; });
  async function test(target: "syslog" | "webhook") {
    try {
      const result = await tester.mutateAsync({ target, sharing: form.getFieldsValue(true), secrets: drafts });
      setResults((current) => ({ ...current, [target]: result }));
    } catch (error) {
      setResults((current) => ({ ...current, [target]: { ok: false, error: errorMessage(error) } }));
    }
  }

  const result = (target: string) => results[target] && <Alert type={results[target].ok ? "success" : "error"} showIcon
    message={results[target].ok ? t("settings.alerting.testOk") : t("settings.alerting.testFailed", { error: results[target].error })} />;

  return <ConfigShell kind="sharing" config={config} canWrite={canWrite} saver={saver}
    onReload={() => { void query.refetch(); }}
    onSave={async (note) => {
      const ok = await saver.submit({ data: await form.validateFields(), note, base_version: config.version,
        ...(Object.keys(drafts).length ? { secrets: drafts } : {}) });
      if (ok) setDrafts({});
      return ok;
    }}>
    <Form form={form} layout="vertical" disabled={!canWrite}>
      <Card size="small" title="STIX"><Space wrap>
        <Form.Item name={["stix", "tlp"]} label="TLP"><Select style={{ width: 120 }} options={["white", "green", "amber", "red"].map((value) => ({ value, label: value.toUpperCase() }))} /></Form.Item>
        <Form.Item name={["stix", "min_severity"]} label={t("settings.sharing.minSeverity")}><Select style={{ width: 140 }} options={SEVERITIES.map((value) => ({ value, label: t(`severity.${value}`) }))} /></Form.Item>
      </Space></Card>
      <Card size="small" title="SIEM"><Space wrap align="start">
        <Form.Item name={["siem", "min_severity"]} label={t("settings.sharing.minSeverity")}><Select style={{ width: 140 }} options={SEVERITIES.map((value) => ({ value, label: t(`severity.${value}`) }))} /></Form.Item>
        <Form.Item name={["siem", "categories"]} label={t("settings.alerting.categories")} extra={t("settings.alerting.categoriesHint")}>
          <Select mode="multiple" allowClear style={{ minWidth: 260 }} options={CATEGORIES.map((value) => ({ value, label: t(`category.${value}`) }))} />
        </Form.Item>
      </Space></Card>
      <Card size="small" title="Syslog">
        <Space wrap align="start">
          <Form.Item name={["siem", "syslog", "enabled"]} label={t("settings.alerting.enabled")} valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name={["siem", "syslog", "host"]} label={t("settings.sharing.host")}><Input style={{ width: 220 }} /></Form.Item>
          <Form.Item name={["siem", "syslog", "port"]} label={t("settings.alerting.smtpPort")}><InputNumber min={1} max={65535} /></Form.Item>
          <Form.Item name={["siem", "syslog", "protocol"]} label={t("settings.sharing.protocol")}><Select style={{ width: 100 }} options={["tls", "tcp", "udp"].map((value) => ({ value, label: value.toUpperCase() }))} /></Form.Item>
          <Form.Item name={["siem", "syslog", "app_name"]} label={t("settings.sharing.appName")}><Input style={{ width: 120 }} /></Form.Item>
        </Space>
        <Form.Item name={["siem", "syslog", "ca_pem"]} label={t("settings.sharing.caPem")} extra={t("settings.sharing.caPemHint")}>
          <Input.TextArea className="opti-mono" rows={4} />
        </Form.Item>
        {canWrite && <Space direction="vertical"><Button onClick={() => { void test("syslog"); }} loading={tester.isPending}>{t("settings.sharing.testSyslog")}</Button>{result("syslog")}</Space>}
      </Card>
      <Card size="small" title="Webhook"><Space wrap align="start">
        <Form.Item name={["siem", "webhook", "enabled"]} label={t("settings.alerting.enabled")} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name={["siem", "webhook", "url"]} label={t("settings.sharing.url")}><Input style={{ width: 320 }} /></Form.Item>
        <Form.Item name={["siem", "webhook", "format"]} label={t("settings.sharing.format")}><Select style={{ width: 160 }} options={[{ value: "json", label: "JSON（HMAC）" }, { value: "splunk_hec", label: "Splunk HEC" }]} /></Form.Item>
        <Form.Item name={["siem", "webhook", "token_header"]} label={t("settings.sharing.tokenHeader")}><Input style={{ width: 160 }} /></Form.Item>
        <Form.Item name={["siem", "webhook", "token_prefix"]} label={t("settings.sharing.tokenPrefix")}><Input style={{ width: 120 }} /></Form.Item>
        <Form.Item name={["siem", "webhook", "timeout_seconds"]} label={t("settings.sharing.timeout")}><InputNumber min={1} max={60} /></Form.Item>
      </Space></Card>
    </Form>
    {canWrite && <Card size="small" title={t("settings.sharing.secrets")}><Form layout="vertical">
      <Form.Item label={t("settings.sharing.signingKey")}>
        <SecretInput label={t("settings.sharing.signingKey")} state={state("siem_signing_key")} draft={drafts.siem_signing_key}
          onChange={(value) => setSecret("siem_signing_key", value)} disabled={!canWrite} keyMissing={keyMissing} />
      </Form.Item>
      <Form.Item label={t("settings.sharing.token")}>
        <SecretInput label={t("settings.sharing.token")} state={state("siem_webhook_token")} draft={drafts.siem_webhook_token}
          onChange={(value) => setSecret("siem_webhook_token", value)} disabled={!canWrite} keyMissing={keyMissing} />
      </Form.Item>
    </Form><Space direction="vertical"><Button onClick={() => { void test("webhook"); }} loading={tester.isPending}>{t("settings.sharing.testWebhook")}</Button>{result("webhook")}</Space></Card>}
  </ConfigShell>;
}
