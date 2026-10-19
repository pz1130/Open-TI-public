import { usePagination } from "../components/pagination";
import { Alert, App, Button, Card, Drawer, Form, Input, Modal, Popconfirm, Radio, Space, Switch, Table, Tag, Tooltip, Typography, type TableProps } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorMessage, type Schemas } from "../api/client";
import { useMe } from "../api/hooks";
import { useAccountCandidates, useCheckProtectedAccount, useProtectedAccounts, useRemoveProtectedAccount, useSaveProtectedAccount, type CandidateSeverity } from "../api/socialAccounts";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import SubmitLeadModal from "../components/SubmitLeadModal";
import { fmtTime } from "../components/format";
import { SeverityTag } from "../components/tags";

type Account = Schemas["ProtectedAccountOut"];
type Candidate = Schemas["AccountCandidateOut"];
type Inputs = { platform: "bluesky" | "mastodon"; handle: string; label: string; queries_text: string; allowed_text: string; enabled: boolean };
const PLATFORMS = { bluesky: "Bluesky", mastodon: "Mastodon" } as const;
const FATAL = new Set(["adapter_disabled", "search_failed", "scan_timeout"]);

function body(row: Account, patch: Partial<Schemas["ProtectedAccountIn"]> = {}): Schemas["ProtectedAccountIn"] {
  return { platform: row.platform as Inputs["platform"], handle: row.handle, label: row.label, extra_queries: row.extra_queries, allowed_accounts: row.allowed_accounts, enabled: row.enabled, ...patch };
}

export default function SocialAccountsPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const writable = can(useMe().data, "watchlist:write");
  const paging = usePagination(null);
  const accounts = useProtectedAccounts(paging.page, paging.pageSize);
  const rows = accounts.data?.items ?? [];
  const [selected, setSelected] = useState<Account | null>(null);
  const [candidateOrder, setCandidateOrder] = useState<"id" | "score_asc" | "score_desc">("score_desc");
  const [severity, setSeverity] = useState<CandidateSeverity | undefined>(undefined);
  const [editing, setEditing] = useState<Account | null>(null);
  const [open, setOpen] = useState(false);
  const [escalate, setEscalate] = useState<string | null>(null);
  const [pending, setPending] = useState<Record<number, { checked: string | null; at: number }>>({});
  const [form] = Form.useForm<Inputs>();
  const save = useSaveProtectedAccount();
  const check = useCheckProtectedAccount();
  const remove = useRemoveProtectedAccount();
  const detailPaging = usePagination([selected?.id, severity, candidateOrder]);
  const candidates = useAccountCandidates(selected?.id ?? null, severity, detailPaging.page, detailPaging.pageSize, candidateOrder);
  const current = rows.find((row) => row.id === selected?.id) ?? selected;
  const onError = (error: unknown) => void message.error(t("common.error", { message: errorMessage(error) }));

  useEffect(() => {
    if (!accounts.data) return;
    setPending((previous) => {
      const next = Object.fromEntries(Object.entries(previous).filter(([id, entry]) => {
        const row = accounts.data.items.find((r) => r.id === Number(id));
        return (!row || (row.enabled && row.last_checked_at === entry.checked)) && Date.now() - entry.at < 15 * 60_000;
      }));
      return Object.keys(next).length === Object.keys(previous).length ? previous : next;
    });
  }, [accounts.data]);

  const edit = (row: Account | null) => {
    setEditing(row);
    form.setFieldsValue({
      platform: (row?.platform as Inputs["platform"]) ?? "bluesky", handle: row?.handle ?? "", label: row?.label ?? "",
      queries_text: row?.extra_queries.join("\n") ?? "", allowed_text: row?.allowed_accounts.join("\n") ?? "", enabled: row?.enabled ?? true,
    });
    setOpen(true);
  };
  // 问题摘要形如 "profile_failed; search_failed:2"，逐项解释
  const explain = (error: string) => error.split("; ").map((part) => {
    const [code, n] = part.split(":");
    return t(`socialAccounts.errors.${code}${n ? "_some" : ""}`, { n, defaultValue: t("socialAccounts.errors.other") });
  }).join("；");
  const status = (row: Account) => {
    if (row.scanning || pending[row.id]) return <Tag color="blue">{t("socialAccounts.checking")}</Tag>;
    if (!row.enabled) return <Tag>{t("socialAccounts.paused")}</Tag>;
    if (!row.adapter_ready) return <Tag color="orange">{t("socialAccounts.adapterOffShort")}</Tag>;
    if (row.error) {
      const key = row.error === "protected_not_found" ? "notFound" : FATAL.has(row.error) ? "failed" : "partial";
      return <Tooltip title={explain(row.error)}><Tag color={key === "notFound" ? "red" : "orange"}>{t(`socialAccounts.${key}`)}</Tag></Tooltip>;
    }
    return row.last_checked_at ? <Tag color="green">{t("socialAccounts.ok")}</Tag> : <Tag>{t("socialAccounts.neverChecked")}</Tag>;
  };
  const allow = (candidate: Candidate) => {
    if (!current) return;
    save.mutate({ id: current.id, body: body(current, { allowed_accounts: [...current.allowed_accounts, candidate.platform_account_id] }) }, {
      onSuccess: () => void message.success(t("socialAccounts.allowed")), onError,
    });
  };

  const columns: TableProps<Account>["columns"] = [
    { title: t("socialAccounts.platform"), dataIndex: "platform", render: (value: keyof typeof PLATFORMS) => PLATFORMS[value] ?? value },
    { title: t("socialAccounts.handle"), dataIndex: "handle", render: (value: string, row) => <Space direction="vertical" size={0}>
      <Typography.Text>{value}</Typography.Text>
      {row.label && <Typography.Text type="secondary">{row.label}</Typography.Text>}
    </Space> },
    { title: t("socialAccounts.displayName"), dataIndex: "display_name", render: (value: string | null) => value ?? "–" },
    { title: t("socialAccounts.status"), render: (_, row) => status(row) },
    { title: t("socialAccounts.candidateCount"), dataIndex: "candidate_count", align: "right" },
    { title: t("socialAccounts.lastChecked"), dataIndex: "last_checked_at", render: fmtTime },
    { title: t("socialAccounts.nextCheck"), render: (_, row) => row.enabled ? fmtTime(row.next_check_at) : "–" },
    { key: "actions", render: (_, row) => <Space wrap>
      <Button size="small" onClick={() => { setSeverity(undefined); setSelected(row); }}>{t("socialAccounts.view")}</Button>
      {writable && <>
        <Button size="small" disabled={!row.enabled} loading={row.scanning || Boolean(pending[row.id]) || (check.isPending && check.variables === row.id)} onClick={() => check.mutate(row.id, {
          onSuccess: () => { setPending((previous) => ({ ...previous, [row.id]: { checked: row.last_checked_at, at: Date.now() } })); void message.success(t("socialAccounts.queued")); }, onError,
        })}>{t("socialAccounts.checkNow")}</Button>
        <Button size="small" onClick={() => edit(row)}>{t("socialAccounts.edit")}</Button>
        <Popconfirm title={t("socialAccounts.removeConfirm")} onConfirm={() => remove.mutate(row.id, { onError, onSuccess: () => { if (selected?.id === row.id) setSelected(null); } })}>
          <Button size="small" danger loading={remove.isPending && remove.variables === row.id}>{t("socialAccounts.remove")}</Button>
        </Popconfirm>
      </>}
    </Space> },
  ];
  const onDetailChange: TableProps<Candidate>["onChange"] = (_, __, sorter, extra) => {
    if (extra.action !== "sort") return;
    const direction = Array.isArray(sorter) ? sorter[0]?.order : sorter.order;
    setCandidateOrder(direction === "ascend" ? "score_asc" : direction === "descend" ? "score_desc" : "id");
  };
  const candidateColumns: TableProps<Candidate>["columns"] = [
    { title: t("socialAccounts.handle"), dataIndex: "handle", render: (value: string, row) => <a href={row.profile_url} target="_blank" rel="noreferrer noopener">{value}</a> },
    { title: t("socialAccounts.displayName"), dataIndex: "display_name" },
    { title: t("socialAccounts.severity"), dataIndex: "severity", render: (value: string) => <SeverityTag value={value} />, sorter: true, sortOrder: candidateOrder === "id" ? null : candidateOrder === "score_asc" ? "ascend" : "descend" },
    { title: t("socialAccounts.signals"), dataIndex: "signals", render: (signals: string[]) => <Space size={[0, 4]} wrap>{signals.map((s) => <Tag key={s}>{t(`reason.${s}`, { defaultValue: s })}</Tag>)}</Space> },
    { title: t("socialAccounts.registeredAt"), dataIndex: "registered_at", render: fmtTime },
    { title: t("socialAccounts.lastSeen"), dataIndex: "last_seen", render: fmtTime },
    { title: t("socialAccounts.status"), render: (_, row) => <Space size={[0, 4]} wrap>
      {row.gone_at && <Tooltip title={fmtTime(row.gone_at)}><Tag color="green">{t("socialAccounts.gone")}</Tag></Tooltip>}
      {row.allowed && <Tag>{t("socialAccounts.allowedTag")}</Tag>}
    </Space> },
    { title: t("socialAccounts.alert"), dataIndex: "alert_id", render: (id: number | null) => id ? <Link to={`/alerts/${id}`}>{`#${id}`}</Link> : "–" },
    ...(writable ? [{ key: "actions", render: (_: unknown, row: Candidate) => <Space wrap>
      {!row.alert_id && !row.gone_at && <Button size="small" onClick={() => setEscalate(row.profile_url)}>{t("socialAccounts.escalate")}</Button>}
      {!row.allowed && <Popconfirm title={t("socialAccounts.allowConfirm")} onConfirm={() => allow(row)}>
        <Button size="small">{t("socialAccounts.allow")}</Button>
      </Popconfirm>}
    </Space> }] : []),
  ];

  return <Card title={t("socialAccounts.title")} extra={writable && <Button type="primary" onClick={() => edit(null)}>{t("socialAccounts.add")}</Button>}>
    <Typography.Paragraph type="secondary">{t("socialAccounts.description")}</Typography.Paragraph>
    {rows.some((row) => !row.adapter_ready) && <Alert showIcon type="warning" style={{ marginBottom: 16 }} message={t("socialAccounts.adapterOff")}
      description={<>{t("socialAccounts.adapterOffHint")} <Link to="/connectors">{t("socialAccounts.connectorSettings")}</Link></>} />}
    <QueryError error={accounts.error} />
    <Table rowKey="id" columns={columns} dataSource={rows} loading={accounts.isLoading} pagination={paging.config(accounts.data?.total)} scroll={{ x: 1100 }} />
    <Modal title={t(`socialAccounts.${editing ? "edit" : "add"}`)} open={open} onCancel={() => { setOpen(false); save.reset(); }} onOk={() => form.submit()} confirmLoading={save.isPending} destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={(values) => save.mutate({ id: editing?.id, body: {
        platform: values.platform, handle: values.handle.trim(), label: values.label.trim(), enabled: values.enabled,
        extra_queries: values.queries_text.split("\n").map((s) => s.trim()).filter(Boolean),
        allowed_accounts: values.allowed_text.split(/[\s,，]+/).map((s) => s.trim()).filter(Boolean),
      } }, { onSuccess: () => setOpen(false), onError })}>
        <Form.Item name="platform" label={t("socialAccounts.platform")}>
          <Radio.Group disabled={Boolean(editing)} options={Object.entries(PLATFORMS).map(([value, label]) => ({ value, label }))} />
        </Form.Item>
        <Form.Item name="handle" label={t("socialAccounts.handle")} rules={[{ required: true }]} extra={t("socialAccounts.handleHint")}>
          <Input disabled={Boolean(editing)} maxLength={300} placeholder="example.bsky.social / user@mastodon.social" />
        </Form.Item>
        <Form.Item name="label" label={t("socialAccounts.label")}><Input maxLength={100} /></Form.Item>
        <Form.Item name="queries_text" label={t("socialAccounts.extraQueries")} extra={t("socialAccounts.extraQueriesHint")}><Input.TextArea rows={3} /></Form.Item>
        <Form.Item name="allowed_text" label={t("socialAccounts.allowedAccounts")} extra={t("socialAccounts.allowedAccountsHint")}><Input.TextArea rows={3} /></Form.Item>
        <Form.Item name="enabled" label={t("socialAccounts.enabled")} valuePropName="checked"><Switch /></Form.Item>
      </Form>
    </Modal>
    <Drawer title={current ? `${t("socialAccounts.view")} · ${current.handle}` : ""} open={selected !== null} onClose={() => setSelected(null)} width="min(1300px, 100vw)">
      {current?.error && <Alert showIcon type="warning" message={explain(current.error)} style={{ marginBottom: 16 }} />}
      <Typography.Paragraph type="secondary">{t("socialAccounts.leadHint")}</Typography.Paragraph>
      {current?.platform === "mastodon" && <Typography.Paragraph type="secondary">{t("socialAccounts.mastodonScope")}</Typography.Paragraph>}
      <Radio.Group optionType="button" value={severity ?? "all"} onChange={(e) => setSeverity(e.target.value === "all" ? undefined : e.target.value as CandidateSeverity)} style={{ marginBottom: 16 }}
        options={[{ value: "all", label: t("socialAccounts.allCandidates") }, { value: "medium", label: t("socialAccounts.mediumAndAbove") }]} />
      <QueryError error={candidates.error} />
      <Table<Candidate> onChange={onDetailChange} rowKey="id" columns={candidateColumns} dataSource={candidates.data?.items ?? []} loading={candidates.isLoading} pagination={detailPaging.config(candidates.data?.total)} scroll={{ x: 1200 }} />
    </Drawer>
    {escalate !== null && <SubmitLeadModal open url={escalate} onClose={() => setEscalate(null)} />}
  </Card>;
}
