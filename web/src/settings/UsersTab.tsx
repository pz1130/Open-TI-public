import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, App, Button, Descriptions, Dropdown, Form, Input, Modal, Select, Space, Switch, Table, Tag, Typography } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { accessKey, useAccessCatalog, useUsers, type ManagedUser } from "../api/access";
import { api, errorMessage, unwrap } from "../api/client";
import { keys, useMe } from "../api/hooks";
import { fmtTime } from "../components/format";
import { listPagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import { roleLabel, setLabel, permissionLabel } from "./accessLabels";

type Values = { username: string; display_name: string; password: string; active: boolean; roles: string[]; permission_sets: string[] };

export default function UsersTab() {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const qc = useQueryClient();
  const me = useMe().data;
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const users = useUsers(q, page, size);
  const catalog = useAccessCatalog();
  const [editing, setEditing] = useState<ManagedUser | "new" | null>(null);
  const [resetting, setResetting] = useState<ManagedUser | null>(null);
  const [viewing, setViewing] = useState<ManagedUser | null>(null);
  const [form] = Form.useForm<Values>();
  const [passwordForm] = Form.useForm<{ password: string; confirm: string }>();
  const roles = Form.useWatch("roles", form) ?? [];
  const sets = Form.useWatch("permission_sets", form) ?? [];
  const superadmin = !!me?.roles.includes("superadmin");
  const canManage = (row: ManagedUser) => superadmin || ![...row.roles, ...row.idp_roles].includes("superadmin");
  const error = (e: unknown) => void message.error(errorMessage(e));
  const refresh = async () => { await qc.invalidateQueries({ queryKey: accessKey }); await qc.invalidateQueries({ queryKey: keys.me }); };
  const action = useMutation({ mutationFn: async (run: () => Promise<unknown>) => run(), onSuccess: refresh, onError: error });
  const edit = (row: ManagedUser | "new") => {
    form.resetFields();
    form.setFieldsValue(row === "new" ? { username: "", display_name: "", active: true, roles: [], permission_sets: [] } : row);
    setEditing(row);
  };
  const save = useMutation({ mutationFn: async (v: Values) => {
    if (editing === "new") return unwrap(await api.POST("/api/v1/admin/users", { body: { username: v.username, display_name: v.display_name ?? "", password: v.password, roles: v.roles ?? [], permission_sets: v.permission_sets ?? [] } }));
    if (!editing) return;
    return unwrap(await api.PUT("/api/v1/admin/users/{user_id}", { params: { path: { user_id: editing.id } }, body: { display_name: v.display_name ?? "", active: v.active, roles: v.roles ?? [], permission_sets: v.permission_sets ?? [], base_version: editing.version } }));
  }, onSuccess: async () => { setEditing(null); form.resetFields(); void message.success(t("access.saved")); await refresh(); }, onError: error });
  const reset = useMutation({ mutationFn: async ({ password }: { password: string }) => {
    if (!resetting) return;
    return unwrap(await api.POST("/api/v1/admin/users/{user_id}/password", { params: { path: { user_id: resetting.id } }, body: { password, base_version: resetting.version } }));
  }, onSuccess: async () => { setResetting(null); passwordForm.resetFields(); void message.success(t("access.passwordResetDone")); await refresh(); }, onError: error });
  const selectedPermissions = new Set<string>([
    ...(catalog.data?.roles.filter((role) => roles.includes(role.name) || (editing && editing !== "new" && editing.idp_roles.includes(role.name))).flatMap((role) => role.permissions) ?? []),
    ...(catalog.data?.permission_sets.filter((set) => sets.includes(set.name)).flatMap((set) => set.permissions) ?? []),
  ]);
  const confirmAction = (title: string, run: () => Promise<unknown>) => modal.confirm({ title, content: t("access.sessionsEffect"), onOk: () => action.mutateAsync(run) });
  return <Space direction="vertical" size={16} style={{ width: "100%" }}>
    <Typography.Title level={4}>{t("settings.tabs.users")}</Typography.Title>
    <Alert type="info" showIcon message={t("access.userHint")} />
    <QueryError error={users.error ?? catalog.error} />
    <Space wrap>
      <Input.Search aria-label={t("access.searchUsers")} placeholder={t("access.searchUsers")} allowClear onSearch={(value) => { setQ(value); setPage(1); }} style={{ width: 260 }} />
      <Button type="primary" onClick={() => edit("new")}>{t("access.createUser")}</Button>
    </Space>
    <Table<ManagedUser> rowKey="id" loading={users.isPending} dataSource={users.data?.items ?? []} scroll={{ x: 930 }} size="small"
      pagination={{ ...listPagination, current: page, pageSize: size, total: users.data?.total ?? 0, onChange: (next, limit) => { setPage(limit !== size ? 1 : next); setSize(limit); } }}
      columns={[
        { title: t("access.username"), dataIndex: "username", render: (value: string, row) => <><Typography.Text strong>{value}</Typography.Text><br /><Typography.Text type="secondary">{row.display_name}</Typography.Text></> },
        { title: t("access.source"), dataIndex: "auth_source", render: (value: string) => <Tag>{t(value === "local" ? "access.local" : "access.sso")}</Tag> },
        { title: t("access.status"), key: "status", render: (_, row) => <Space wrap><Tag color={row.active ? "green" : undefined}>{t(row.active ? "access.active" : "access.disabled")}</Tag>{row.must_change_password && <Tag color="orange">{t("access.mustChange")}</Tag>}{row.locked_until && Date.parse(row.locked_until) > Date.now() && <Tag color="red">{t("access.locked")}</Tag>}</Space> },
        { title: t("access.roles"), key: "roles", render: (_, row) => [...new Set([...row.roles, ...row.idp_roles])].map((name) => <Tag key={name}>{roleLabel(t, catalog.data?.roles.find((r) => r.name === name) ?? { name, display_name: name, builtin: false, description: "", permissions: [], permission_sets: [], version: 0 })}</Tag>) },
        { title: t("access.lastLogin"), dataIndex: "last_login_at", render: fmtTime },
        { title: t("access.actions"), key: "actions", width: 250, render: (_, row) => <Space wrap>
          <Button size="small" onClick={() => setViewing(row)}>{t("access.effectivePermissions")}</Button>
          <Button size="small" disabled={!canManage(row)} onClick={() => edit(row)}>{t("access.edit")}</Button>
          <Dropdown trigger={["click"]} menu={{ items: [
            { key: "password", label: t("access.resetPassword"), disabled: row.auth_source !== "local", onClick: () => { passwordForm.resetFields(); setResetting(row); } },
            { key: "active", label: t(row.active ? "access.disableUser" : "access.enableUser"), danger: row.active, onClick: () => confirmAction(t(row.active ? "access.disableUser" : "access.enableUser"), async () => unwrap(await api.PUT("/api/v1/admin/users/{user_id}", { params: { path: { user_id: row.id } }, body: { display_name: row.display_name, active: !row.active, roles: row.roles, permission_sets: row.permission_sets, base_version: row.version } }))) },
            { key: "unlock", label: t("access.unlock"), onClick: () => confirmAction(t("access.unlock"), async () => unwrap(await api.POST("/api/v1/admin/users/{user_id}/unlock", { params: { path: { user_id: row.id }, query: { base_version: row.version } } }))) },
            { key: "sessions", label: t("access.revokeSessions"), danger: true, onClick: () => confirmAction(t("access.revokeSessions"), async () => unwrap(await api.DELETE("/api/v1/admin/users/{user_id}/sessions", { params: { path: { user_id: row.id }, query: { base_version: row.version } } }))) },
          ] }}><Button size="small" disabled={!canManage(row)}>{t("access.more")}</Button></Dropdown>
        </Space> },
      ]} />
    <Modal open={editing !== null} title={t(editing === "new" ? "access.createUser" : "access.editUser")} onCancel={() => { setEditing(null); form.resetFields(); }} footer={null} destroyOnHidden width={720}>
      <Form form={form} layout="vertical" onFinish={(v) => save.mutate(v)}>
        <Form.Item name="username" label={t("access.username")} rules={[{ required: true, pattern: /^[a-z0-9._-]{2,64}$/, message: t("access.usernameHint") }]}><Input disabled={editing !== "new"} autoComplete="off" /></Form.Item>
        <Form.Item name="display_name" label={t("access.displayName")}><Input maxLength={100} /></Form.Item>
        {editing === "new" && <Form.Item name="password" label={t("access.initialPassword")} rules={[{ required: true, min: 12, message: t("access.passwordHint") }]}><Input.Password autoComplete="new-password" maxLength={1000} /></Form.Item>}
        {editing !== "new" && <Form.Item name="active" label={t("access.active")} valuePropName="checked"><Switch /></Form.Item>}
        {editing && editing !== "new" && editing.auth_source === "oidc" && <Alert type="info" message={t("access.idpRoles", { roles: editing.idp_roles.join(", ") || "—" })} style={{ marginBottom: 16 }} />}
        <Form.Item name="roles" label={t("access.roles")}><Select mode="multiple" aria-label={t("access.roles")} optionFilterProp="label" options={(catalog.data?.roles ?? []).filter((r) => superadmin || r.name !== "superadmin").map((r) => ({ value: r.name, label: `${roleLabel(t, r)} (${r.name})` }))} /></Form.Item>
        <Form.Item name="permission_sets" label={t("access.permissionSets")}><Select mode="multiple" aria-label={t("access.permissionSets")} optionFilterProp="label" options={(catalog.data?.permission_sets ?? []).map((s) => ({ value: s.name, label: `${setLabel(t, s)} (${s.permissions.length})` }))} /></Form.Item>
        <Typography.Paragraph type="secondary">{t("access.assignmentHint")}</Typography.Paragraph>
        <Typography.Text strong>{t("access.permissionPreview", { count: selectedPermissions.size })}</Typography.Text>
        <div style={{ maxHeight: 180, overflow: "auto", marginBottom: 16 }}>{(catalog.data?.permissions ?? []).filter((p) => selectedPermissions.has(p.id)).map((p) => <Tag key={p.id} title={p.id}>{permissionLabel(t, p.id, p.description)}</Tag>)}</div>
        <Button type="primary" htmlType="submit" loading={save.isPending}>{t("access.save")}</Button>
      </Form>
    </Modal>
    <Modal open={resetting !== null} title={t("access.resetPassword")} footer={null} onCancel={() => { setResetting(null); passwordForm.resetFields(); }} destroyOnHidden>
      <Alert type="info" message={t("access.resetHint")} style={{ marginBottom: 16 }} />
      <Form form={passwordForm} layout="vertical" onFinish={(v) => reset.mutate(v)}>
        <Form.Item name="password" label={t("access.newPassword")} rules={[{ required: true, min: 12, message: t("access.passwordHint") }]}><Input.Password autoComplete="new-password" maxLength={1000} /></Form.Item>
        <Form.Item name="confirm" label={t("access.confirmPassword")} dependencies={["password"]} rules={[{ required: true }, ({ getFieldValue }) => ({ validator: (_, value) => value === getFieldValue("password") ? Promise.resolve() : Promise.reject(new Error(t("access.passwordMismatch"))) })]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Button type="primary" htmlType="submit" loading={reset.isPending}>{t("access.save")}</Button>
      </Form>
    </Modal>
    <Modal open={viewing !== null} title={t("access.effectivePermissions")} onCancel={() => setViewing(null)} footer={null} width={720}>
      {viewing && <><Descriptions items={[{ key: "username", label: t("access.username"), children: viewing.username }, { key: "sets", label: t("access.permissionSets"), children: viewing.permission_sets.join(", ") || "—" }]} />
        <Table size="small" rowKey="id" pagination={listPagination} dataSource={(catalog.data?.permissions ?? []).filter((p) => viewing.permissions.includes(p.id))} columns={[{ title: t("access.permission"), dataIndex: "id" }, { title: t("access.meaning"), key: "description", render: (_, p) => permissionLabel(t, p.id, p.description) }]} /></>}
    </Modal>
  </Space>;
}
