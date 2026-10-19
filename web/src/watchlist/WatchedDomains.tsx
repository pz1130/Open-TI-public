import { usePagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import { App, Button, Drawer, Form, Image, Input, Modal, Pagination, Select, Space, Switch, Table, Timeline, Typography, type TableProps } from "antd";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage, type Schemas } from "../api/client";
import { WatchCheckUnconfirmed } from "../api/watchChecks";
import { evidenceUrl, useAddWatch, useCheckWatch, useMe, useRemoveWatch, useUpdateWatch, useWatchObservations, useWatchlist, type WatchFilters } from "../api/hooks";
import { can } from "../auth/perms";
import DomainText from "../components/DomainText";
import { fmtTime } from "../components/format";
import { WatchStateTag } from "../components/tags";
import WatchPagePanel, { WatchPageTag } from "../components/WatchPagePanel";

type Row = Schemas["WatchOut"];
type Checking = { lastCheckedAt: string | null; startedAt: number };
const CHECK_TIMEOUT_MS = 10 * 60_000;
const isExpired = (row: Row) => row.expires_at !== null && Date.parse(row.expires_at) <= Date.now();

export default function WatchedDomains() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const me = useMe().data;
  const writable = can(me, "watchlist:write");
  const [filters, setFilters] = useState<WatchFilters>({ includeExpired: false });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Row | null>(null);
  const [removing, setRemoving] = useState<Row | null>(null);
  const [checking, setChecking] = useState<Record<number, Checking>>({});
  const [submitting, setSubmitting] = useState<Record<number, boolean>>({});
  const pendingChecks = useRef(new Set<number>());
  const [timelineFor, setTimelineFor] = useState<Row | null>(null);
  const [pageFor, setPageFor] = useState<Row | null>(null);
  const [historySelection, setHistorySelection] = useState("latest");
  const paging = usePagination(filters);
  const q = useWatchlist(filters, paging.page, paging.pageSize);
  const add = useAddWatch();
  const update = useUpdateWatch();
  const check = useCheckWatch();
  const remove = useRemoveWatch();
  const timelinePaging = usePagination(timelineFor?.id);
  const observations = useWatchObservations(timelineFor?.id ?? null);
  const pageHistory = useWatchObservations(pageFor?.id ?? null, true);
  const [addForm] = Form.useForm<Schemas["WatchIn"]>();
  const [editForm] = Form.useForm<Schemas["WatchIn"]>();
  const [removeForm] = Form.useForm<{ reason: string }>();
  const rows = q.data?.items ?? [];
  const historical = pageHistory.data?.find((row) => String(row.id ?? row.observed_at) === historySelection);
  const displayedInspection = historySelection === "latest"
    ? pageHistory.data?.[0]?.inspection ?? rows.find((row) => row.id === pageFor?.id)?.inspection
    : historical?.inspection;
  const onError = (e: unknown) => void message.error(t("common.error", { message: errorMessage(e) }));

  const submitCheck = async (row: Row) => {
    if (pendingChecks.current.has(row.id) || checking[row.id]) return;
    pendingChecks.current.add(row.id);
    setSubmitting((previous) => ({ ...previous, [row.id]: true }));
    try {
      await check.mutateAsync(row.id);
      setChecking((previous) => ({ ...previous, [row.id]: { lastCheckedAt: row.last_checked_at, startedAt: Date.now() } }));
      void q.refetch();
      void message.success(t("watchlist.checkQueued"));
    } catch (error) {
      if (error instanceof WatchCheckUnconfirmed) {
        void message.warning(t("watchlist.checkUnconfirmed"));
        void q.refetch();
      } else onError(error);
    } finally {
      pendingChecks.current.delete(row.id);
      setSubmitting((previous) => { const next = { ...previous }; delete next[row.id]; return next; });
    }
  };

  useEffect(() => {
    if (!q.data) return;
    const current = new Map(q.data.items.map((row) => [row.id, row]));
    setChecking((previous) => {
      let changed = false;
      const next = { ...previous };
      for (const [key, started] of Object.entries(previous)) {
        const id = Number(key);
        const checkedAt = current.get(id)?.last_checked_at;
        if (checkedAt && checkedAt !== started.lastCheckedAt) {
          delete next[id];
          changed = true;
        }
      }
      return changed ? next : previous;
    });
  }, [q.data]);

  const activeChecks = Object.keys(checking).length;
  useEffect(() => {
    if (!activeChecks) return;
    const timer = window.setInterval(() => {
      void q.refetch();
      setChecking((previous) => {
        const next = Object.fromEntries(
          Object.entries(previous).filter(([, value]) => Date.now() - value.startedAt < CHECK_TIMEOUT_MS),
        );
        return Object.keys(next).length === Object.keys(previous).length ? previous : next;
      });
    }, 3000);
    return () => window.clearInterval(timer);
  }, [activeChecks, q.refetch]);

  const columns: TableProps<Row>["columns"] = [
    { title: t("watchlist.domain"), dataIndex: "domain", render: (v: string, row: Row) => <Space direction="vertical" size={4}><DomainText value={v} /><Button size="small" onClick={() => { setPageFor(row); setHistorySelection("latest"); }}>{t("watchlist.viewPage")}</Button></Space> },
    {
      title: t("watchlist.state"),
      dataIndex: "state",
      render: (v: string, r: Row) => (isExpired(r) ? <Typography.Text type="secondary">{t("watchlist.removed")}</Typography.Text> : r.inspection && !["no_dns", "mx_only"].includes(v) ? <WatchPageTag verdict={r.inspection.verdict} /> : <WatchStateTag value={v} />),
    },
    { title: t("watchlist.pageTitle"), key: "page", width: 240, render: (_, row) => row.inspection?.title || "–", ellipsis: true },
    { title: t("watchlist.screenshot"), key: "screenshot", width: 100, render: (_, row) => {
      const screenshot = row.inspection?.evidence?.find((e) => e.kind === "screenshot");
      return can(me, "evidence:read") && screenshot ? <Image src={evidenceUrl(screenshot.id)} alt={t("watchlist.screenshot")} width={72} height={48} style={{ objectFit: "cover" }} loading="lazy" preview={false} /> : "–";
    } },
    { title: t("watchlist.reason"), dataIndex: "reason", ellipsis: true },
    { title: t("watchlist.createdAt"), dataIndex: "created_at", render: (v: string) => fmtTime(v) },
    { title: t("watchlist.lastChecked"), dataIndex: "last_checked_at", render: (v: string | null) => fmtTime(v) },
    { title: t("watchlist.nextCheck"), dataIndex: "next_check_at", render: (v: string) => fmtTime(v) },
    {
      key: "actions",
      render: (_: unknown, r: Row) => (
        <Space>
          <Button size="small" onClick={() => setTimelineFor(r)}>{t("watchlist.timeline")}</Button>
          {writable && !isExpired(r) && (
            <Button size="small" htmlType="button" title={t("watchlist.checkHint")}
              loading={Boolean(checking[r.id]) || submitting[r.id]}
              onClick={() => void submitCheck(r)}>
              {checking[r.id] ? t("watchlist.checking") : t("watchlist.checkNow")}
            </Button>
          )}
          {writable && !isExpired(r) && (
            <Button size="small" onClick={() => {
              editForm.setFieldsValue({ domain: r.domain, reason: r.reason });
              setEditing(r);
            }}>{t("watchlist.edit")}</Button>
          )}
          {writable && !isExpired(r) && (
            <Button size="small" danger onClick={() => setRemoving(r)}>{t("watchlist.remove")}</Button>
          )}
        </Space>
      ),
    },
  ];

  return (
    <>
      <QueryError error={q.error} />
      <Space wrap style={{ marginBottom: 16 }}>
        {writable && <Button type="primary" onClick={() => setAdding(true)}>{t("watchlist.add")}</Button>}
        <Input.Search allowClear style={{ width: 240 }} placeholder={t("watchlist.domain")}
          onSearch={(v) => setFilters({ ...filters, q: v.trim() || undefined })} />
        <Space>
          <Switch checked={filters.includeExpired} onChange={(includeExpired) => setFilters({ ...filters, includeExpired })} />
          {t("watchlist.includeExpired")}
        </Space>
      </Space>
      <Table<Row> rowKey="id" size="middle" loading={q.isPending} dataSource={rows} columns={columns} pagination={paging.config(q.data?.total)} scroll={{ x: 1500 }} />

      <Modal open={adding} title={t("watchlist.add")} footer={null} onCancel={() => setAdding(false)} destroyOnHidden>
        <Form form={addForm} name="watch-add" layout="vertical"
          onFinish={(v) => add.mutate(v, {
            onSuccess: () => { void message.success(t("watchlist.added")); setAdding(false); addForm.resetFields(); },
            onError,
          })}>
          <Form.Item name="domain" label={t("watchlist.domain")} extra={t("watchlist.domainHint")} rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="reason" label={t("watchlist.reason")} rules={[{ required: true }]}><Input maxLength={500} /></Form.Item>
          <Button type="primary" htmlType="submit" loading={add.isPending}>{t("common.submit")}</Button>
        </Form>
      </Modal>

      <Modal open={editing !== null} title={t("watchlist.edit")} footer={null}
        onCancel={() => setEditing(null)} destroyOnHidden>
        <Form form={editForm} name="watch-edit" layout="vertical"
          onFinish={(body) => editing && update.mutate({ id: editing.id, body }, {
            onSuccess: () => { void message.success(t("watchlist.updated")); setEditing(null); editForm.resetFields(); },
            onError,
          })}>
          <Form.Item name="domain" label={t("watchlist.domain")}
            extra={<>{t("watchlist.domainHint")} {t("watchlist.editDomainHint")}</>}
            rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="reason" label={t("watchlist.reason")} rules={[{ required: true }]}><Input maxLength={500} /></Form.Item>
          <Button type="primary" htmlType="submit" loading={update.isPending}>{t("watchlist.save")}</Button>
        </Form>
      </Modal>

      <Modal open={removing !== null} title={removing?.domain} footer={null} onCancel={() => setRemoving(null)} destroyOnHidden>
        <Form form={removeForm} name="watch-remove" layout="vertical"
          onFinish={(v) => removing && remove.mutate({ id: removing.id, reason: v.reason ?? "" }, {
            onSuccess: () => { void message.success(t("watchlist.removedDone")); setRemoving(null); removeForm.resetFields(); },
            onError,
          })}>
          <Form.Item name="reason" label={t("watchlist.removeReason")}><Input maxLength={500} /></Form.Item>
          <Button type="primary" danger htmlType="submit" loading={remove.isPending}>{t("common.submit")}</Button>
        </Form>
      </Modal>

      <Drawer open={timelineFor !== null} title={timelineFor?.domain} onClose={() => setTimelineFor(null)} width={480}>
        <QueryError error={observations.error} />
        <Timeline
          items={(observations.data ?? []).slice((timelinePaging.page - 1) * timelinePaging.pageSize, timelinePaging.page * timelinePaging.pageSize).map((o) => ({
            children: (
              <Space direction="vertical" size={0}>
                <span>{fmtTime(o.observed_at)} · <WatchStateTag value={o.state} /></span>
                {o.changes.length > 0 && <Typography.Text type="secondary">{o.changes.join(", ")}</Typography.Text>}
              </Space>
            ),
          }))}
        />
        <Pagination {...timelinePaging.config(observations.data?.length)} />
      </Drawer>
      <Drawer open={pageFor !== null} title={`${pageFor?.domain ?? ""} · ${t("watchlist.viewPage")}`} onClose={() => setPageFor(null)} width="min(860px, 100vw)">
        <QueryError error={pageHistory.error} />
        {(pageHistory.data?.length ?? 0) > 1 && <Select style={{ width: "100%", marginBottom: 16 }} value={historySelection}
          aria-label={t("watchlist.pageHistory")} onChange={setHistorySelection}
          options={pageHistory.data?.map((row, index) => ({ value: index === 0 ? "latest" : String(row.id ?? row.observed_at), label: `${fmtTime(row.observed_at)} · ${row.inspection ? t(`watchlist.pageKinds.${row.inspection.verdict}`) : t(`watchState.${row.state}`)}` }))} />}
        <WatchPagePanel inspection={displayedInspection} canView={can(me, "evidence:read")} />
      </Drawer>
    </>
  );
}
