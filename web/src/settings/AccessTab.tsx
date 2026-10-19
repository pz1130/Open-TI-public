import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, App, Button, Checkbox, Form, Input, Modal, Select, Space, Table, Tabs, Tag, Typography } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { accessKey, useAccessCatalog, type AccessRole, type PermissionSet } from "../api/access";
import { api, errorMessage, unwrap } from "../api/client";
import { keys } from "../api/hooks";
import { listPagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import { permissionLabel, roleLabel, setLabel } from "./accessLabels";

type Kind = "roles" | "permission-sets";
type Draft = { name: string; display_name: string; description: string; permission_sets: string[]; permissions: string[] };

export default function AccessTab() {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const qc = useQueryClient();
  const catalog = useAccessCatalog();
  const [editing, setEditing] = useState<{ kind: Kind; row: AccessRole | PermissionSet | null } | null>(null);
  const [viewing, setViewing] = useState<AccessRole | PermissionSet | null>(null);
  const [form] = Form.useForm<Draft>();
  const chosenSets: string[] = Form.useWatch("permission_sets", form) ?? [];
  const chosenPermissions: string[] = Form.useWatch("permissions", form) ?? [];
  const refresh = async () => { await qc.invalidateQueries({ queryKey: accessKey }); await qc.invalidateQueries({ queryKey: keys.me }); };
  const error = (e: unknown) => void message.error(errorMessage(e));
  const save = useMutation({ mutationFn: async (v: Draft) => {
    const common = { name: v.name, display_name: v.display_name, description: v.description ?? "", base_version: editing?.row?.version ?? 0 };
    return editing?.kind === "roles"
      ? unwrap(await api.PUT("/api/v1/admin/access/roles/{name}", { params: { path: { name: v.name } }, body: { ...common, permission_sets: v.permission_sets ?? [] } }))
      : unwrap(await api.PUT("/api/v1/admin/access/permission-sets/{name}", { params: { path: { name: v.name } }, body: { ...common, permissions: v.permissions ?? [] } }));
  }, onSuccess: async () => { setEditing(null); form.resetFields(); void message.success(t("access.saved")); await refresh(); }, onError: error });
  const remove = useMutation({ mutationFn: async ({ kind, row }: { kind: Kind; row: PermissionSet }) => unwrap(await api.DELETE("/api/v1/admin/access/{kind}/{name}", { params: { path: { kind, name: row.name }, query: { base_version: row.version } } })), onSuccess: refresh, onError: error });
  const edit = (kind: Kind, row: AccessRole | PermissionSet | null) => {
    form.resetFields();
    form.setFieldsValue(row ? { ...row, permission_sets: "permission_sets" in row ? row.permission_sets : [] } : { name: "", display_name: "", description: "", permission_sets: [], permissions: [] });
    setEditing({ kind, row });
  };
  const permissionsTable = (ids: string[]) => <Table size="small" rowKey="id" pagination={listPagination}
    dataSource={(catalog.data?.permissions ?? []).filter((p) => ids.includes(p.id))}
    columns={[{ title: t("access.permission"), dataIndex: "id" }, { title: t("access.meaning"), key: "meaning", render: (_, p) => permissionLabel(t, p.id, p.description) }]} />;
  const definitions = (kind: Kind) => <Space direction="vertical" style={{ width: "100%" }} size={16}>
    <Button type="primary" onClick={() => edit(kind, null)}>{t(kind === "roles" ? "access.createRole" : "access.createSet")}</Button>
    <Table<AccessRole | PermissionSet> size="small" rowKey="name" pagination={listPagination} scroll={{ x: 760 }} loading={catalog.isPending}
      dataSource={kind === "roles" ? catalog.data?.roles : catalog.data?.permission_sets}
      columns={[
        { title: t("access.name"), key: "name", render: (_, row) => <><Typography.Text strong>{kind === "roles" ? roleLabel(t, row as AccessRole) : setLabel(t, row)}</Typography.Text><br /><Typography.Text code>{row.name}</Typography.Text></> },
        { title: t("access.type"), dataIndex: "builtin", render: (builtin: boolean) => <Tag>{t(builtin ? "access.builtin" : "access.custom")}</Tag> },
        { title: t("access.description"), dataIndex: "description", render: (value: string, row) => row.builtin ? t(row.name === "superadmin" ? "access.superadminHint" : "access.builtinHint") : value },
        { title: t("access.permissionCount"), key: "count", render: (_, row) => row.permissions.length },
        { title: t("access.actions"), key: "actions", render: (_, row) => <Space>
          <Button size="small" onClick={() => setViewing(row)}>{t("access.view")}</Button>
          {!row.builtin && <><Button size="small" onClick={() => edit(kind, row)}>{t("access.edit")}</Button>
            <Button size="small" danger onClick={() => modal.confirm({ title: t("access.deleteTitle", { name: row.display_name }), content: t("access.deleteHint"), onOk: () => remove.mutateAsync({ kind, row }) })}>{t("access.delete")}</Button></>}
        </Space> },
      ]} />
  </Space>;
  const preview = editing?.kind === "roles"
    ? [...new Set((catalog.data?.permission_sets ?? []).filter((s) => chosenSets.includes(s.name)).flatMap((s) => s.permissions))]
    : chosenPermissions;
  return <Space direction="vertical" size={16} style={{ width: "100%" }}>
    <Typography.Title level={4}>{t("settings.tabs.access")}</Typography.Title>
    <Alert type="info" showIcon message={t("access.modelHint")} />
    <Alert type="warning" showIcon message={t("access.adminPowerHint")} />
    <QueryError error={catalog.error} />
    <Tabs items={[
      { key: "roles", label: t("access.roles"), children: definitions("roles") },
      { key: "sets", label: t("access.permissionSets"), children: definitions("permission-sets") },
      { key: "permissions", label: t("access.permissionCatalog"), children: permissionsTable((catalog.data?.permissions ?? []).map((p) => p.id)) },
    ]} />
    <Modal open={editing !== null} title={t(editing?.kind === "roles" ? "access.editRole" : "access.editSet")} footer={null} onCancel={() => { setEditing(null); form.resetFields(); }} destroyOnHidden width={760}>
      <Form form={form} layout="vertical" onFinish={(v) => save.mutate(v)}>
        <Form.Item name="name" label={t("access.identifier")} extra={t("access.identifierHint")} rules={[{ required: true, pattern: /^[a-z][a-z0-9_-]{1,63}$/, message: t("access.identifierHint") }]}><Input disabled={!!editing?.row} maxLength={64} /></Form.Item>
        <Form.Item name="display_name" label={t("access.name")} rules={[{ required: true, whitespace: true }]}><Input maxLength={100} /></Form.Item>
        <Form.Item name="description" label={t("access.description")}><Input.TextArea maxLength={1000} rows={2} /></Form.Item>
        {editing?.kind === "roles" ? <Form.Item name="permission_sets" label={t("access.permissionSets")}><Select mode="multiple" aria-label={t("access.permissionSets")} optionFilterProp="label" options={(catalog.data?.permission_sets ?? []).map((s) => ({ value: s.name, label: `${setLabel(t, s)} (${s.permissions.length})` }))} /></Form.Item>
          : <Form.Item name="permissions" label={t("access.permissions")}><Checkbox.Group style={{ width: "100%" }}>
            <Space direction="vertical" style={{ width: "100%", maxHeight: 360, overflow: "auto" }}>
              {(catalog.data?.permissions ?? []).map((p) => <Checkbox key={p.id} value={p.id}><Typography.Text>{permissionLabel(t, p.id, p.description)}</Typography.Text> <Typography.Text type="secondary">{p.id}</Typography.Text></Checkbox>)}
            </Space>
          </Checkbox.Group></Form.Item>}
        <Typography.Paragraph type="secondary">{t("access.permissionPreview", { count: preview.length })}</Typography.Paragraph>
        {editing?.kind === "roles" && <div style={{ maxHeight: 180, overflow: "auto", marginBottom: 16 }}>{(catalog.data?.permissions ?? []).filter((p) => preview.includes(p.id)).map((p) => <Tag key={p.id}>{permissionLabel(t, p.id, p.description)}</Tag>)}</div>}
        <Button type="primary" htmlType="submit" loading={save.isPending}>{t("access.save")}</Button>
      </Form>
    </Modal>
    <Modal open={viewing !== null} title={viewing?.display_name} onCancel={() => setViewing(null)} footer={null} width={760}>
      {viewing && <><Typography.Paragraph type="secondary">{viewing.builtin ? t(viewing.name === "superadmin" ? "access.superadminHint" : "access.builtinHint") : viewing.description}</Typography.Paragraph>
        {"permission_sets" in viewing && viewing.permission_sets.map((name) => <Tag key={name}>{setLabel(t, catalog.data?.permission_sets.find((s) => s.name === name) ?? { name, display_name: name, description: "", permissions: [], builtin: false, version: 0 })}</Tag>)}
        {permissionsTable(viewing.permissions)}</>}
    </Modal>
  </Space>;
}
