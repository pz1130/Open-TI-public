import { Button, Form, Input, Space, Spin } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useConfig, useMe } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import HistoryDrawer from "./HistoryDrawer";
import SaveFeedback from "./SaveFeedback";
import StatusBar from "./StatusBar";
import { useConfigSaver } from "./useConfigSaver";

const FIELDS = ["name", "short_name", "website", "security_contact", "legal_statement", "legal_statement_en", "takedown_sender", "signature"] as const;
const NULLABLE = new Set<string>(["website", "security_contact", "takedown_sender"]);
const LONG = new Set<string>(["legal_statement", "legal_statement_en"]);

export default function OrganizationTab() {
  const { t } = useTranslation();
  const me = useMe();
  const q = useConfig("organization");
  const saver = useConfigSaver("organization");
  const [form] = Form.useForm();
  const [note, setNote] = useState("");
  const [history, setHistory] = useState(false);
  const canWrite = can(me.data, "organization:write");

  useEffect(() => {
    if (q.data) form.setFieldsValue(q.data.data);
  }, [q.data, form]);

  if (q.isPending) return <Spin />;
  if (q.isError && !q.data) return <QueryError error={q.error} />;
  const config = q.data;

  async function onSave() {
    const values = (await form.validateFields()) as Record<string, string | null | undefined>;
    const data = Object.fromEntries(FIELDS.map((f) => [f, NULLABLE.has(f) && !values[f] ? null : (values[f] ?? "")]));
    if (await saver.submit({ data, note: note.trim() || null, base_version: config.version, confirm_project_change: false, confirm_oidc_change: false })) setNote("");
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <StatusBar kind="organization" config={config} />
      <SaveFeedback
        errors={saver.errors}
        conflict={saver.conflict}
        onHistory={() => setHistory(true)}
        onReload={() =>
          q.refetch().then((r) => {
            if (r.isError || !r.data) return;
            form.setFieldsValue(r.data.data);
            saver.clearConflict();
          })
        }
      />
      <Form form={form} layout="vertical" disabled={!canWrite} className="oti-config-form">
        {FIELDS.map((f) => (
          <Form.Item key={f} name={f} label={t(`settings.org.${f}`)} rules={f === "name" ? [{ required: true, message: t("settings.required") }] : []}>
            {LONG.has(f) ? <Input.TextArea rows={3} /> : <Input />}
          </Form.Item>
        ))}
      </Form>
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
        kind="organization"
        open={history}
        onClose={() => setHistory(false)}
        current={config.version}
        canWrite={canWrite}
        onRestore={(v) => saver.restore(v, config.version).then((ok) => ok && setHistory(false))}
      />
    </Space>
  );
}
