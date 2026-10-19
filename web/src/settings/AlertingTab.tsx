import { PlusOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Form, Input, InputNumber, Select, Space, Spin, Switch } from "antd";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAlertingSecrets, useConfig, useMe, useTestAlertingChannel, type AlertingTestResult } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import { dropChannelSecret, moveChannelSecret, publishableSecrets, secretName, type SecretDraft } from "./alertingForm";
import ChannelCard from "./ChannelCard";
import HistoryDrawer from "./HistoryDrawer";
import SaveFeedback from "./SaveFeedback";
import SecretInput from "./SecretInput";
import StatusBar from "./StatusBar";
import { useConfigSaver } from "./useConfigSaver";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ZONES: string[] = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? ["UTC", "Asia/Shanghai"];

type Channel = Record<string, unknown> & { id: string; type: "teams" | "email" };

export default function AlertingTab() {
  const { t } = useTranslation();
  const me = useMe();
  const canWrite = can(me.data, "alerting:write");
  const q = useConfig("alerting");
  const secrets = useAlertingSecrets(canWrite);
  const saver = useConfigSaver("alerting");
  const tester = useTestAlertingChannel();
  const [form] = Form.useForm();
  const [drafts, setDrafts] = useState<SecretDraft>({});
  const [note, setNote] = useState("");
  const [history, setHistory] = useState(false);
  const [results, setResults] = useState<Record<number, AlertingTestResult>>({});
  const [testingIndex, setTestingIndex] = useState<number | null>(null);
  const secretIds = useRef(new Map<number, string>());
  const savedIds = useMemo(
    () => new Set(((q.data?.data.channels ?? []) as Channel[]).map((c) => c.id)),
    [q.data],
  );
  const keyMissing = secrets.data?.encryption_key === false;

  useEffect(() => {
    if (q.data) {
      form.setFieldsValue(q.data.data);
      setDrafts({});
      secretIds.current.clear();
      setResults({});
    }
  }, [q.data, form]);

  if (q.isPending) return <Spin />;
  if (q.isError && !q.data) return <QueryError error={q.error} />;
  const config = q.data;

  const setSecret = (name: string, v: string | null | undefined) =>
    setDrafts((d) => {
      const next = { ...d };
      if (v === undefined) delete next[name];
      else next[name] = v;
      return next;
    });

  const moveSecret = (fieldKey: number, watchedPrev: string, nextId: string) => {
    const prev = secretIds.current.has(fieldKey) ? secretIds.current.get(fieldKey)! : watchedPrev;
    if (prev === nextId) return;
    secretIds.current.set(fieldKey, nextId);
    setDrafts((d) => moveChannelSecret(d, fieldKey, prev, nextId));
  };

  async function onSave() {
    const values = await form.validateFields();
    const secrets = publishableSecrets(drafts);
    const body = {
      data: values,
      note: note.trim() || null,
      base_version: config.version,
      confirm_project_change: false,
      confirm_oidc_change: false,
      ...(Object.keys(secrets).length ? { secrets } : {}),
    };
    if (await saver.submit(body)) {
      setNote("");
      setDrafts({});
      secretIds.current.clear();
    }
  }

  async function onTest(index: number) {
    const channel = form.getFieldValue(["channels", index]) as Channel;
    setTestingIndex(index);
    try {
      const secretsDraft = Object.fromEntries(
        Object.entries(publishableSecrets(drafts)).filter((e): e is [string, string] => typeof e[1] === "string"),
      );
      const r = await tester.mutateAsync({
        channel,
        smtp: channel.type === "email" ? form.getFieldValue("smtp") : null,
        secrets: secretsDraft,
      });
      setResults((m) => ({ ...m, [index]: r }));
    } finally {
      setTestingIndex(null);
    }
  }

  const smtpState = (name: string) => secrets.data?.secrets.find((s) => s.name === name);
  const savedChannels = (config.data.channels ?? []) as Channel[];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <StatusBar kind="alerting" config={config} />
      <SaveFeedback
        errors={saver.errors}
        conflict={saver.conflict}
        onHistory={() => setHistory(true)}
        onReload={() =>
          q.refetch().then((r) => {
            if (r.isError || !r.data) return;
            form.setFieldsValue(r.data.data);
            setDrafts({});
            secretIds.current.clear();
            setResults({});
            saver.clearConflict();
          })
        }
      />
      <Form form={form} layout="vertical" disabled={!canWrite}>
        <Card size="small" title={t("settings.alerting.basic")}>
          <Form.Item name="public_base_url" label={t("settings.alerting.publicBaseUrl")} rules={[{ required: true, message: t("settings.required") }]}>
            <Input />
          </Form.Item>
          <Space wrap align="start">
            <Form.Item name="digest" label={t("settings.alerting.digest")}>
              <Select mode="multiple" style={{ minWidth: 220 }} options={SEVERITIES.map((s) => ({ value: s, label: t(`severity.${s}`) }))} />
            </Form.Item>
            <Form.Item name="report_language" label={t("settings.alerting.language")}>
              <Select style={{ width: 140 }} options={[{ value: "zh-CN", label: "中文" }, { value: "en-US", label: "English" }]} />
            </Form.Item>
            <Form.Item name="report_timezone" label={t("settings.alerting.timezone")}>
              <Select showSearch style={{ width: 240 }} options={ZONES.map((z) => ({ value: z }))} />
            </Form.Item>
          </Space>
        </Card>
        <Card size="small" title={t("settings.alerting.smtp")}>
          <Space wrap align="start">
            <Form.Item name={["smtp", "host"]} label={t("settings.alerting.smtpHost")}><Input style={{ width: 220 }} /></Form.Item>
            <Form.Item name={["smtp", "port"]} label={t("settings.alerting.smtpPort")}><InputNumber min={1} max={65535} /></Form.Item>
            <Form.Item name={["smtp", "starttls"]} label="STARTTLS" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name={["smtp", "sender"]} label={t("settings.alerting.smtpSender")}><Input style={{ width: 240 }} /></Form.Item>
          </Space>
          {canWrite && (
            <Space wrap align="start" style={{ width: "100%" }}>
              <Form.Item label={t("settings.alerting.smtpUsername")} style={{ minWidth: 280 }}>
                <SecretInput label={t("settings.alerting.smtpUsername")} state={smtpState("smtp_username")} draft={drafts.smtp_username}
                  onChange={(v) => setSecret("smtp_username", v)} disabled={!canWrite} keyMissing={keyMissing} />
              </Form.Item>
              <Form.Item label={t("settings.alerting.smtpPassword")} style={{ minWidth: 280 }}>
                <SecretInput label={t("settings.alerting.smtpPassword")} state={smtpState("smtp_password")} draft={drafts.smtp_password}
                  onChange={(v) => setSecret("smtp_password", v)} disabled={!canWrite} keyMissing={keyMissing} />
              </Form.Item>
            </Space>
          )}
        </Card>
        <Form.List name="channels">
          {(fields, { add, remove }) => (
            <Space direction="vertical" style={{ width: "100%" }}>
              {fields.map((field) => (
                <ChannelCard
                  key={field.key}
                  field={field}
                  locked={savedIds.has(form.getFieldValue(["channels", field.name, "id"]))}
                  disabled={!canWrite}
                  keyMissing={keyMissing}
                  secrets={secrets.data?.secrets}
                  drafts={drafts}
                  onSecret={setSecret}
                  onSecretMove={(prev, next) => moveSecret(field.key, prev, next)}
                  onRemove={() => {
                    const channelId = String(form.getFieldValue(["channels", field.name, "id"]) ?? "");
                    const tracked = secretIds.current.get(field.key) ?? "";
                    secretIds.current.delete(field.key);
                    setDrafts((d) => dropChannelSecret(d, field.key, channelId, tracked));
                    remove(field.name);
                  }}
                  onTest={() => onTest(field.name)}
                  testing={testingIndex === field.name}
                  testResult={results[field.name]}
                />
              ))}
              {canWrite && (
                <Space>
                  {(["teams", "email"] as const).map((type) => (
                    <Button key={type} icon={<PlusOutlined aria-hidden />} onClick={() => add({
                      id: "", name: "", type, enabled: true, severities: ["critical", "high"], categories: [],
                      reports: [], notices: false, recipients: [],
                    })}>
                      {t(`settings.alerting.add.${type}`)}
                    </Button>
                  ))}
                </Space>
              )}
            </Space>
          )}
        </Form.List>
      </Form>
      {canWrite && secrets.data && savedChannels.some((c) => c.type === "teams" && !secrets.data?.secrets.find((s) => s.name === secretName(c.id))?.set) && (
        <Alert type="warning" showIcon message={t("settings.alerting.missingWebhook")} />
      )}
      <Space wrap>
        <Button onClick={() => setHistory(true)}>{t("settings.history.open")}</Button>
        {canWrite && (
          <>
            <Input style={{ width: 280 }} placeholder={t("settings.note")} value={note} maxLength={200} onChange={(e) => setNote(e.target.value)} />
            <Button type="primary" loading={saver.pending} onClick={onSave}>{t("settings.save")}</Button>
          </>
        )}
      </Space>
      <HistoryDrawer
        kind="alerting"
        open={history}
        onClose={() => setHistory(false)}
        current={config.version}
        canWrite={canWrite}
        onRestore={(v) => saver.restore(v, config.version).then((ok) => ok && setHistory(false))}
      />
    </Space>
  );
}
