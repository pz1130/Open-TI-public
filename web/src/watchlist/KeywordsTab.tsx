import { App, Button, Card, Form, List, Modal, Select, Space, Table, Tag, Typography, type TableProps } from "antd";
import { useState } from "react";
import { Link } from "react-router";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../api/client";
import { useDomainKeywords, useKeywordBackfill, useMe, useRemoveKeyword, useUpdateAffixes, type KeywordKind } from "../api/hooks";
import { can } from "../auth/perms";
import { fmtTime } from "../components/format";
import { listPagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import KeywordScanPanel from "../components/KeywordScanPanel";
import KeywordAddModal from "./KeywordAddModal";
import KeywordDomainsDrawer from "./KeywordDomainsDrawer";
import { CONNECTOR_NAMES, backfillLines, changeMessage, keywordError } from "./keywordText";

type Stat = Schemas["KeywordStatOut"];
type Restricted = Schemas["RestrictedKeywordOut"];

export default function KeywordsTab() {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const me = useMe().data;
  const canEdit = can(me, "rules:write");
  const canRun = can(me, "watchlist:write");
  const q = useDomainKeywords();
  const remove = useRemoveKeyword();
  const updateAffixes = useUpdateAffixes();
  const backfill = useKeywordBackfill();
  const [adding, setAdding] = useState<KeywordKind | null>(null);
  const [viewing, setViewing] = useState<{ kind: KeywordKind; value: string } | null>(null);
  const [editing, setEditing] = useState<Restricted | null>(null);
  const [affixForm] = Form.useForm<{ affixes: string[] }>();
  const data = q.data;
  const onError = (e: unknown) => void message.error(t("common.error", { message: keywordError(t, e) }));

  const confirmRemove = (kind: KeywordKind, value: string) => modal.confirm({
    title: t("watchlist.keywords.removeTitle", { value }),
    content: t("watchlist.keywords.removeBody"),
    okButtonProps: { danger: true },
    onOk: () => remove.mutateAsync({ kind, value }).then((r) => void message.success(changeMessage(t, r)), onError),
  });

  const valueColumn = { title: t("watchlist.keywords.value"), dataIndex: "value", width: 220, render: (v: string) => <Typography.Text code style={{ whiteSpace: "nowrap" }}>{v}</Typography.Text> };
  const findingsColumn = { title: t("watchlist.keywords.findings30d"), dataIndex: "findings_30d", width: 140, render: (n: number | null) => n ?? "—" };
  const lastSeenColumn = { title: t("watchlist.keywords.lastSeen"), dataIndex: "last_seen", width: 180, render: (v: string | null) => fmtTime(v) };
  const statColumns = (kind: KeywordKind): TableProps<Stat>["columns"] => [
    valueColumn, findingsColumn, lastSeenColumn,
    { key: "actions", width: 200, render: (_: unknown, r: Stat) => (
      <Space>
        <Button size="small" onClick={() => setViewing({ kind, value: r.value })}>{t("watchlist.keywords.view")}</Button>
        {canEdit && <Button size="small" danger onClick={() => confirmRemove(kind, r.value)}>{t("watchlist.keywords.remove")}</Button>}
      </Space>
    ) },
  ];
  const restrictedColumns: TableProps<Restricted>["columns"] = [
    valueColumn,
    { title: t("watchlist.keywords.affixes"), dataIndex: "affixes", render: (a: string[]) => a.map((x) => <Tag key={x}>{x}</Tag>) },
    findingsColumn, lastSeenColumn,
    { key: "actions", width: 260, render: (_: unknown, r: Restricted) => (
      <Space>
        <Button size="small" onClick={() => setViewing({ kind: "restricted", value: r.value })}>{t("watchlist.keywords.view")}</Button>
        {canEdit && <Button size="small" onClick={() => { affixForm.setFieldsValue({ affixes: r.affixes }); setEditing(r); }}>{t("watchlist.keywords.editAffixes")}</Button>}
        {canEdit && <Button size="small" danger onClick={() => confirmRemove("restricted", r.value)}>{t("watchlist.keywords.remove")}</Button>}
      </Space>
    ) },
  ];
  const addButton = (kind: KeywordKind) =>
    canEdit && <Button size="small" onClick={() => setAdding(kind)}>{t("watchlist.keywords.add")}</Button>;

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>{t("watchlist.keywords.intro")}</Typography.Paragraph>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
        {t("watchlist.keywords.textScopeHint")}
        {can(me, "rules:test") && <> <Link to="/settings/rules">{t("watchlist.keywords.openTextRules")}</Link></>}
      </Typography.Paragraph>
      <QueryError error={q.error} />
      {canEdit && data && <KeywordScanPanel version={data.version} domainTerms={[...data.brand.map((item) => item.value), ...data.restricted.map((item) => item.value)]} />}
      <Card size="small" title={t("watchlist.keywords.backfillTitle")}
        extra={canRun && (
          <Button size="small" loading={backfill.isPending} onClick={() => backfill.mutate(undefined, {
            onSuccess: (r) => void message.info(backfillLines(t, r).join("；")),
            onError,
          })}>{t("watchlist.keywords.backfillNow")}</Button>
        )}>
        <Space wrap size={24}>
          {Object.entries(data?.last_runs ?? {}).map(([id, run]) => (
            <span key={id}>
              <Typography.Text strong>{CONNECTOR_NAMES[id] ?? id}</Typography.Text>{" "}
              {run ? <>
                <Tag>{t(`watchlist.keywords.runStatus.${run.status}`, { defaultValue: run.status })}</Tag>
                {fmtTime(run.started_at)} · {t("watchlist.keywords.runItems", { count: run.items })}
              </> : <Typography.Text type="secondary">{t("watchlist.keywords.neverRun")}</Typography.Text>}
            </span>
          ))}
        </Space>
      </Card>
      <Card size="small" title={t("watchlist.keywords.kinds.brand")} extra={addButton("brand")}>
        <Table<Stat> rowKey="value" size="small" pagination={listPagination} scroll={{ x: 760 }} loading={q.isPending} dataSource={data?.brand ?? []} columns={statColumns("brand")} />
      </Card>
      <Card size="small" title={t("watchlist.keywords.kinds.restricted")} extra={addButton("restricted")}>
        <Typography.Paragraph type="secondary">{t("watchlist.keywords.restrictedHint")}</Typography.Paragraph>
        <Table<Restricted> rowKey="value" size="small" pagination={listPagination} scroll={{ x: 760 }} loading={q.isPending} dataSource={data?.restricted ?? []} columns={restrictedColumns} />
      </Card>
      <Card size="small" title={t("watchlist.keywords.kinds.official")} extra={addButton("official")}>
        <Table<Stat> rowKey="value" size="small" pagination={listPagination} scroll={{ x: 760 }} loading={q.isPending} dataSource={data?.official ?? []} columns={statColumns("official")} />
      </Card>
      <Card size="small" title={t("watchlist.keywords.kinds.lookalike")} extra={addButton("lookalike")}>
        <Typography.Paragraph type="secondary">{t("watchlist.keywords.lookalikeHint")}</Typography.Paragraph>
        <List<string> size="small" dataSource={data?.lookalike ?? []} pagination={listPagination}
          renderItem={(d) => (
            <List.Item key={d}>
              <Tag closable={canEdit} onClose={(e) => { e.preventDefault(); confirmRemove("lookalike", d); }}>{d}</Tag>
            </List.Item>
          )} />
      </Card>

      <KeywordAddModal open={adding !== null} initialKind={adding ?? "brand"} shortMax={data?.short_token_max_len ?? 4}
        canTest={can(me, "rules:test")} onClose={() => setAdding(null)} />
      <KeywordDomainsDrawer kind={viewing?.kind ?? "brand"} value={viewing?.value ?? null} canEdit={canEdit} onClose={() => setViewing(null)} />
      <Modal open={editing !== null} title={t("watchlist.keywords.editAffixesTitle", { value: editing?.value })} footer={null}
        onCancel={() => setEditing(null)} destroyOnHidden>
        <Form form={affixForm} name="keyword-affixes" layout="vertical"
          onFinish={(v) => editing && updateAffixes.mutate({ token: editing.value, affixes: v.affixes }, {
            onSuccess: (r) => { void message.success(changeMessage(t, r)); setEditing(null); },
            onError,
          })}>
          <Form.Item name="affixes" label={t("watchlist.keywords.affixes")} rules={[{ required: true, type: "array", min: 1 }]}>
            <Select mode="tags" tokenSeparators={[",", " "]} open={false} aria-label={t("watchlist.keywords.affixes")} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={updateAffixes.isPending}>{t("watchlist.save")}</Button>
        </Form>
      </Modal>
    </Space>
  );
}
