import { usePagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import { App, Button, Card, Form, Input, InputNumber, Modal, Popconfirm, Radio, Space, Switch, Table, Tag, type TableProps } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorMessage, type Schemas } from "../api/client";
import { useCreateSuppression, useMe, useRevokeSuppression, useSuppressions } from "../api/hooks";
import { can } from "../auth/perms";
import { fmtTime } from "../components/format";

type Row = Schemas["SuppressionOut"];
interface Values {
  kind: "domain" | "registered_domain";
  value: string;
  reason: string;
  expires_days?: number | null;
}

export default function SuppressionsPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const writable = can(useMe().data, "suppressions:write");
  const [includeInactive, setIncludeInactive] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form] = Form.useForm<Values>();
  const paging = usePagination(includeInactive);
  const q = useSuppressions(includeInactive);
  const create = useCreateSuppression();
  const revoke = useRevokeSuppression();
  const onError = (e: unknown) => void message.error(t("common.error", { message: errorMessage(e) }));

  const columns: TableProps<Row>["columns"] = [
    { title: t("suppressions.kind"), dataIndex: "kind", render: (v: string) => t(`suppressions.kinds.${v}`, { defaultValue: v }) },
    { title: t("suppressions.value"), dataIndex: "value", render: (v: string) => <span className="opti-mono">{v}</span> },
    { title: t("suppressions.reason"), dataIndex: "reason", ellipsis: true },
    { title: t("suppressions.createdBy"), dataIndex: "created_by" },
    { title: t("suppressions.createdAt"), dataIndex: "created_at", render: (v: string) => fmtTime(v) },
    { title: t("suppressions.expiresAt"), dataIndex: "expires_at", render: (v: string | null) => (v ? fmtTime(v) : t("suppressions.never")) },
    {
      title: t("suppressions.sourceAlert"),
      dataIndex: "source_alert_id",
      render: (v: number | null) => (v ? <Link to={`/alerts/${v}`}>#{v}</Link> : null),
    },
    {
      key: "state",
      render: (_: unknown, r: Row) =>
        r.active ? <Tag color="green">{t("suppressions.active")}</Tag> : <Tag>{t("suppressions.inactive")}</Tag>,
    },
    {
      key: "actions",
      render: (_: unknown, r: Row) =>
        writable && r.active ? (
          <Popconfirm
            title={t("suppressions.revokeConfirm")}
            onConfirm={() =>
              revoke.mutate(r.id, { onSuccess: () => void message.success(t("suppressions.revoked")), onError })
            }
          >
            <Button size="small" danger>{t("suppressions.revoke")}</Button>
          </Popconfirm>
        ) : null,
    },
  ];

  return (
    <Card
      title={t("suppressions.title")}
      extra={writable && <Button type="primary" onClick={() => setCreating(true)}>{t("suppressions.add")}</Button>}
    >
      <QueryError error={q.error} />
      <Space style={{ marginBottom: 16 }}>
        <Switch checked={includeInactive} onChange={setIncludeInactive} />
        {t("suppressions.includeInactive")}
      </Space>
      <Table<Row> rowKey="id" size="middle" loading={q.isPending} dataSource={q.data ?? []} columns={columns} pagination={paging.config(q.data?.length)} />
      <Modal open={creating} title={t("suppressions.add")} footer={null} onCancel={() => setCreating(false)} destroyOnHidden>
        <Form<Values>
          form={form}
          name="suppression"
          layout="vertical"
          initialValues={{ kind: "registered_domain" }}
          onFinish={(v) =>
            create.mutate(
              { kind: v.kind, value: v.value, reason: v.reason, expires_days: v.expires_days ?? null },
              {
                onSuccess: () => {
                  void message.success(t("suppressions.created"));
                  setCreating(false);
                  form.resetFields();
                },
                onError,
              },
            )
          }
        >
          <Form.Item name="kind" label={t("suppressions.kind")} rules={[{ required: true }]}>
            <Radio.Group
              options={[
                { value: "domain", label: t("suppressions.kinds.domain") },
                { value: "registered_domain", label: t("suppressions.kinds.registered_domain") },
              ]}
            />
          </Form.Item>
          <Form.Item name="value" label={t("suppressions.value")} rules={[{ required: true }]}><Input className="opti-mono" /></Form.Item>
          <Form.Item name="reason" label={t("suppressions.reason")} rules={[{ required: true }]}><Input maxLength={2000} /></Form.Item>
          <Form.Item name="expires_days" label={t("suppressions.expiresDays")}><InputNumber min={1} max={3650} /></Form.Item>
          <Button type="primary" htmlType="submit" loading={create.isPending}>{t("common.submit")}</Button>
        </Form>
      </Modal>
    </Card>
  );
}
