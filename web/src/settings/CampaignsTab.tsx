import { App, Checkbox, Form, InputNumber, Spin } from "antd";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useConfig, useMe } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import ConfigShell from "./ConfigShell";
import { useConfigSaver } from "./useConfigSaver";

const SIGNALS = ["tls_sha256", "favicon_sha256", "html_sha256", "ip"];

export default function CampaignsTab() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const me = useMe();
  const q = useConfig("campaigns");
  const saver = useConfigSaver("campaigns");
  const [form] = Form.useForm();
  const canWrite = can(me.data, "config:write");
  useEffect(() => { if (q.data) form.setFieldsValue(q.data.data); }, [q.data, form]);
  if (q.isPending) return <Spin />;
  if (q.isError) return <QueryError error={q.error} />;
  const config = q.data;
  return (
    <ConfigShell kind="campaigns" config={config} canWrite={canWrite} saver={saver}
      onReload={() => { void q.refetch().then((r) => {
        if (!r.isError && r.data) { form.setFieldsValue(r.data.data); saver.clearConflict(); }
      }); }}
      onSave={async (note) => {
        const ok = await saver.submit({ data: await form.validateFields(), note, base_version: config.version });
        if (ok) message.info(t("settings.campaigns.recomputing"));
        return ok;
      }}>
      <Form form={form} layout="vertical" disabled={!canWrite} className="oti-config-form">
        <Form.Item name="window_days" label={t("settings.campaigns.window")} extra={t("settings.campaigns.windowHelp")}><InputNumber min={1} max={3650} /></Form.Item>
        <Form.Item name="max_share" label={t("settings.campaigns.maxShare")} extra={t("settings.campaigns.maxShareHelp")}><InputNumber min={2} max={1000} /></Form.Item>
        <Form.Item name="min_members" label={t("settings.campaigns.minMembers")}><InputNumber min={2} max={100} /></Form.Item>
        <Form.Item name="signals" label={t("settings.campaigns.signals")}
          rules={[{ required: true, type: "array", min: 1, message: t("settings.required") }]}>
          <Checkbox.Group options={SIGNALS.map((s) => ({ value: s, label: t(`settings.campaigns.signal.${s}`) }))} />
        </Form.Item>
      </Form>
    </ConfigShell>
  );
}
