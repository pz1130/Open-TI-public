import { usePagination } from "../components/pagination";
import { Alert, App, Button, Card, Drawer, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Tooltip, Typography, type TableProps } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage, type Schemas } from "../api/client";
import { useCertificateHosts, useCertificateMonitors, useCheckCertificateMonitor, useConfigureCertificateHost, useRemoveCertificateMonitor, useSaveCertificateMonitor } from "../api/certificates";
import { useMe } from "../api/hooks";
import { can } from "../auth/perms";
import DomainText from "../components/DomainText";
import QueryError from "../components/QueryError";
import { fmtTime } from "../components/format";

type Monitor = Schemas["CertificateMonitorOut"];
type Host = Schemas["MonitoredCertificateOut"];
type Inputs = { root_domain: string; known_text: string; warn_days: number; enabled: boolean };
const COLORS: Record<string, string> = { healthy: "green", expiring: "orange", expired: "red", error: "default", unknown: "default", retired: "default" };

export default function CertificatesPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const writable = can(useMe().data, "certificates:write");
  const approver = can(useMe().data, "certificates:approve");
  const paging = usePagination(null);
  const monitors = useCertificateMonitors(paging.page, paging.pageSize);
  const rows = monitors.data?.items ?? [];
  const [selected, setSelected] = useState<Monitor | null>(null);
  const [hostOrder, setHostOrder] = useState<"id" | "expiry_asc" | "expiry_desc">("id");
  const [search, setSearch] = useState("");
  const [approval, setApproval] = useState<"all" | "pending" | "approved">("all");
  const [configuring, setConfiguring] = useState<Host | null>(null);
  const [hostForm] = Form.useForm<{ approved: boolean; warn_days: number | null }>();
  const configure = useConfigureCertificateHost();
  const [editing, setEditing] = useState<Monitor | null>(null);
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState<Record<number, { checked: string | null; at: number }>>({});
  const [form] = Form.useForm<Inputs>();
  const save = useSaveCertificateMonitor();
  const check = useCheckCertificateMonitor();
  const remove = useRemoveCertificateMonitor();
  const detailPaging = usePagination([selected?.id, search, hostOrder, approval]);
  const hosts = useCertificateHosts(selected?.id ?? null, search, detailPaging.page, detailPaging.pageSize, hostOrder, approval);
  const current = rows.find((row) => row.id === selected?.id) ?? selected;
  const onError = (error: unknown) => void message.error(t("common.error", { message: errorMessage(error) }));

  useEffect(() => {
    if (!monitors.data) return;
    setPending((previous) => {
      const next = Object.fromEntries(Object.entries(previous).filter(([id, entry]) => {
        const row = monitors.data.items.find((r) => r.id === Number(id));
        return (!row || (row.enabled && row.last_checked_at === entry.checked)) && Date.now() - entry.at < 15 * 60_000;
      }));
      return Object.keys(next).length === Object.keys(previous).length ? previous : next;
    });
  }, [monitors.data]);

  const edit = (row: Monitor | null) => {
    setEditing(row);
    form.setFieldsValue({ root_domain: row?.root_domain ?? "", known_text: row?.known_domains.join("\n") ?? "", warn_days: row?.warn_days ?? 30, enabled: row?.enabled ?? true });
    setOpen(true);
  };
  const hostError = (error: string | null) => t(`certificates.errors.${error}`, { defaultValue: t("certificates.errors.other") });
  const columns: TableProps<Monitor>["columns"] = [
    { title: t("certificates.root"), dataIndex: "root_domain", render: (value: string) => <DomainText value={value} /> },
    { title: t("certificates.status"), render: (_, row) => <Space>
      <Tag color={row.scanning || pending[row.id] ? "blue" : row.enabled ? "green" : "default"}>{t(`certificates.${row.scanning || pending[row.id] ? "checking" : row.enabled ? "enabled" : "paused"}`)}</Tag>
      {row.error && <Tag color="orange">{t("certificates.partialFailure")}</Tag>}
      {row.truncated && <Tag color="orange">{t("certificates.truncatedShort")}</Tag>}
    </Space> },
    { title: t("certificates.hostCount"), dataIndex: "host_count", align: "right" },
    { title: t("certificates.warnDays"), dataIndex: "warn_days", render: (days: number) => t("certificates.dayCount", { days }) },
    { title: t("certificates.lastChecked"), dataIndex: "last_checked_at", render: fmtTime },
    { title: t("certificates.nextCheck"), render: (_, row) => row.enabled ? fmtTime(row.next_check_at) : "–" },
    { key: "actions", render: (_, row) => <Space wrap>
      <Button size="small" onClick={() => { setSearch(""); setSelected(row); }}>{t("certificates.view")}</Button>
      {writable && <>
        <Button size="small" disabled={!row.enabled} loading={row.scanning || Boolean(pending[row.id]) || (check.isPending && check.variables === row.id)} onClick={() => check.mutate(row.id, {
          onSuccess: () => { setPending((previous) => ({ ...previous, [row.id]: { checked: row.last_checked_at, at: Date.now() } })); void message.success(t("certificates.queued")); }, onError,
        })}>{t("certificates.checkNow")}</Button>
        <Button size="small" onClick={() => edit(row)}>{t("certificates.edit")}</Button>
        <Popconfirm title={t("certificates.removeConfirm")} onConfirm={() => remove.mutate(row.id, { onError, onSuccess: () => { if (selected?.id === row.id) setSelected(null); } })}>
          <Button size="small" danger loading={remove.isPending && remove.variables === row.id}>{t("certificates.remove")}</Button>
        </Popconfirm>
      </>}
    </Space> },
  ];
  const onDetailChange: TableProps<Host>["onChange"] = (_, __, sorter, extra) => {
    if (extra.action !== "sort") return;
    const direction = Array.isArray(sorter) ? sorter[0]?.order : sorter.order;
    setHostOrder(direction === "ascend" ? "expiry_asc" : direction === "descend" ? "expiry_desc" : "id");
  };
  const hostColumns: TableProps<Host>["columns"] = [
    { title: t("certificates.domain"), dataIndex: "domain", render: (value: string) => <DomainText value={value} /> },
    { title: t("certificates.approval"), render: (_, row) => <Tag color={row.approved ? "green" : "gold"}>{t(row.approved ? "certificates.approved" : "certificates.pendingApproval")}</Tag> },
    { title: t("certificates.status"), dataIndex: "state", render: (state: string, row) => <Tooltip title={state === "retired" ? t("certificates.retiredHint") : row.error ? hostError(row.error) : undefined}><Tag color={COLORS[state]}>{t(`certificates.states.${state}`, { defaultValue: state })}</Tag></Tooltip> },
    { title: t("certificates.expiresAt"), dataIndex: "not_after", render: (value: string | null, row) => <Tooltip title={row.state === "error" && value ? t("certificates.previousCertificate", { time: fmtTime(row.certificate_checked_at) }) : undefined}>{fmtTime(value)}</Tooltip> },
    { title: t("certificates.daysRemaining"), dataIndex: "days_remaining", align: "right", render: (days: number | null) => days === null ? "–" : t("certificates.dayCount", { days }), sorter: true, sortOrder: hostOrder === "id" ? null : hostOrder === "expiry_asc" ? "ascend" : "descend" },
    { title: t("certificates.issuer"), dataIndex: "issuer" },
    { title: t("certificates.lastChecked"), dataIndex: "checked_at", render: fmtTime },
    { title: t("certificates.warnDays"), render: (_, row) => row.warn_days ? t("certificates.dayCount", { days: row.warn_days }) : t("certificates.inheritDays", { days: current?.warn_days }) },
    ...(approver ? [{ key: "configure", render: (_: unknown, row: Host) => <Space>
      {!row.approved && <Button size="small" loading={configure.isPending && configure.variables?.hostId === row.id}
        onClick={() => selected && configure.mutate({ monitorId: selected.id, hostId: row.id, body: { approved: true, warn_days: row.warn_days } }, { onError })}>{t("certificates.approve")}</Button>}
      <Button size="small" onClick={() => { setConfiguring(row); hostForm.setFieldsValue({ approved: row.approved, warn_days: row.warn_days }); }}>{t("certificates.configureHost")}</Button>
    </Space> }] : []),
  ];

  return <Card title={t("certificates.title")} extra={writable && <Button type="primary" onClick={() => edit(null)}>{t("certificates.add")}</Button>}>
    <Typography.Paragraph type="secondary">{t("certificates.description")}</Typography.Paragraph>
    <QueryError error={monitors.error} />
    <Table rowKey="id" columns={columns} dataSource={rows} loading={monitors.isLoading} pagination={paging.config(monitors.data?.total)} scroll={{ x: 1050 }} />
    <Modal title={t(`certificates.${editing ? "edit" : "add"}`)} open={open} onCancel={() => { setOpen(false); save.reset(); }} onOk={() => form.submit()} confirmLoading={save.isPending} destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={(values) => save.mutate({ id: editing?.id, body: {
        root_domain: values.root_domain.trim(), warn_days: values.warn_days, enabled: values.enabled,
        known_domains: values.known_text.split(/[\s,，]+/).map((s) => s.trim()).filter(Boolean),
      } }, { onSuccess: () => setOpen(false), onError })}>
        <Form.Item name="root_domain" label={t("certificates.root")} rules={[{ required: true }]} extra={editing ? undefined : t("certificates.rootHint")}><Input placeholder="example.com" disabled={Boolean(editing)} maxLength={253} /></Form.Item>
        <Form.Item name="known_text" label={t("certificates.knownDomains")} extra={t("certificates.knownHint")}><Input.TextArea rows={4} placeholder={"www.example.com\nmail.example.com"} /></Form.Item>
        <Form.Item name="warn_days" label={t("certificates.warnDays")} rules={[{ required: true }]}><InputNumber min={1} max={365} /></Form.Item>
        <Form.Item name="enabled" label={t("certificates.enabled")} valuePropName="checked"><Switch /></Form.Item>
        <Typography.Paragraph type="secondary">{t("certificates.scopeHint")}</Typography.Paragraph>
      </Form>
    </Modal>
    <Drawer title={current ? `${t("certificates.view")} · ${current.root_domain}` : ""} open={selected !== null} onClose={() => { setConfiguring(null); setSelected(null); }} width="min(1200px, 100vw)">
      {current?.error && <Alert showIcon type="warning" message={t("certificates.partialFailure")} description={t("certificates.failureHint")} style={{ marginBottom: 16 }} />}
      {current?.truncated && <Alert showIcon type="warning" message={t("certificates.truncated")} style={{ marginBottom: 16 }} />}
      <Typography.Paragraph type="secondary">{t("certificates.scopeHint")}</Typography.Paragraph>
      <Typography.Paragraph type="secondary">{t("certificates.approvalHint")}</Typography.Paragraph>
      <Space style={{ marginBottom: 16 }}>
        <Input.Search allowClear placeholder={t("certificates.search")} onSearch={setSearch} style={{ width: 300 }} />
        <Select aria-label={t("certificates.approval")} value={approval} style={{ minWidth: 150 }}
          options={["all", "pending", "approved"].map((value) => ({ value, label: t(`certificates.approvalView.${value}`) }))}
          onChange={setApproval} />
      </Space>
      <QueryError error={hosts.error} />
      <Table<Host> onChange={onDetailChange} rowKey="id" columns={hostColumns} dataSource={hosts.data?.items ?? []} loading={hosts.isLoading} pagination={detailPaging.config(hosts.data?.total)} scroll={{ x: 950 }} />
    </Drawer>
    <Modal zIndex={1200} title={configuring ? `${t("certificates.configureHost")} · ${configuring.domain}` : ""} open={configuring !== null}
      onCancel={() => setConfiguring(null)} onOk={() => hostForm.submit()} confirmLoading={configure.isPending} destroyOnHidden>
      <Form form={hostForm} layout="vertical" onFinish={(values) => selected && configuring && configure.mutate({
        monitorId: selected.id, hostId: configuring.id, body: { approved: values.approved, warn_days: values.warn_days ?? null },
      }, { onSuccess: () => setConfiguring(null), onError })}>
        <Form.Item name="approved" label={t("certificates.approved")} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="warn_days" label={t("certificates.warnDays")} extra={t("certificates.inheritHint")}><InputNumber min={1} max={365} placeholder={String(current?.warn_days ?? 30)} /></Form.Item>
        <Typography.Paragraph type="secondary">{t("certificates.approvalHint")}</Typography.Paragraph>
      </Form>
    </Modal>
  </Card>;
}
