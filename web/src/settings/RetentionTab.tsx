import { Form, InputNumber, Spin } from "antd";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useConfig, useMe } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import ConfigShell from "./ConfigShell";
import { useConfigSaver } from "./useConfigSaver";

export const RETENTION_FIELDS: [string, number][] = [
  ["raw_items_days", 7], ["report_contacts_days", 0], ["exposed_accounts_days", 1], ["documents_days", 1],
  ["findings_days", 30], ["cases_days", 30], ["connector_runs_days", 7], ["reports_days", 30],
];

export default function RetentionTab() {
  const { t } = useTranslation();
  const me = useMe();
  const q = useConfig("retention");
  const saver = useConfigSaver("retention");
  const [form] = Form.useForm();
  const canWrite = can(me.data, "config:write");
  useEffect(() => { if (q.data) form.setFieldsValue(q.data.data); }, [q.data, form]);
  if (q.isPending) return <Spin />;
  if (q.isError) return <QueryError error={q.error} />;
  const config = q.data;
  return (
    <ConfigShell kind="retention" config={config} canWrite={canWrite} saver={saver}
      onReload={() => { void q.refetch().then((r) => {
        if (!r.isError && r.data) { form.setFieldsValue(r.data.data); saver.clearConflict(); }
      }); }}
      onSave={async (note) => saver.submit({ data: await form.validateFields(), note, base_version: config.version })}>
      <Form form={form} layout="vertical" disabled={!canWrite} className="oti-config-form">
        {RETENTION_FIELDS.map(([name, min]) => (
          <Form.Item key={name} name={name} label={t(`settings.retention.field.${name}`)}
            extra={t(`settings.retention.help.${name}`, { min })}
            rules={[{ required: true, type: "number", min, message: t("settings.retention.min", { min }) }]}>
            <InputNumber min={min} suffix={t("settings.retention.days")} style={{ width: 200 }} />
          </Form.Item>
        ))}
      </Form>
    </ConfigShell>
  );
}
