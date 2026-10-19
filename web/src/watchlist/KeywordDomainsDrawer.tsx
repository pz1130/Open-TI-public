import { App, Button, Drawer, Space, Table, type TableProps } from "antd";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { Schemas } from "../api/client";
import { useAddKeyword, useKeywordDomains, type KeywordKind } from "../api/hooks";
import DomainText from "../components/DomainText";
import { fmtTime } from "../components/format";
import { usePagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import { AlertStatusTag, SeverityTag } from "../components/tags";
import { changeMessage, keywordError } from "./keywordText";

type Row = Schemas["KeywordHitOut"];
const OPEN_ALERT = new Set(["open", "acknowledged"]);

export default function KeywordDomainsDrawer({ kind, value, canEdit, onClose }: {
  kind: KeywordKind; value: string | null; canEdit: boolean; onClose: () => void;
}) {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const paging = usePagination([kind, value]);
  const q = useKeywordDomains(kind, value, paging.page, paging.pageSize);
  const add = useAddKeyword();

  const markLegit = (row: Row) => modal.confirm({
    title: t("watchlist.keywords.markLegitTitle", { domain: row.domain }),
    content: t("watchlist.keywords.markLegitBody"),
    onOk: () => add.mutateAsync({ kind: "lookalike", value: row.domain, affixes: [] }).then(
      (r) => {
        void message.success(changeMessage(t, r));
        if (row.alert_id !== null && OPEN_ALERT.has(row.alert_status ?? "")) {
          void message.warning(t("watchlist.keywords.openAlertLeft", { id: row.alert_id }));
        }
      },
      (e: unknown) => void message.error(t("common.error", { message: keywordError(t, e) })),
    ),
  });

  const columns: TableProps<Row>["columns"] = [
    { title: t("watchlist.domain"), dataIndex: "domain", render: (d: string) => <DomainText value={d} /> },
    { title: t("watchlist.keywords.score"), dataIndex: "score", width: 80 },
    { title: t("watchlist.keywords.severity"), dataIndex: "severity", render: (s: string) => <SeverityTag value={s} /> },
    { title: t("watchlist.keywords.alert"), key: "alert", render: (_: unknown, r: Row) => (r.alert_id !== null ? (
      <Space size={4}><Link to={`/alerts/${r.alert_id}`}>#{r.alert_id}</Link>{r.alert_status && <AlertStatusTag value={r.alert_status} />}</Space>
    ) : "–") },
    { title: t("watchlist.keywords.lastSeen"), dataIndex: "last_seen", render: (v: string) => fmtTime(v) },
    ...(canEdit ? [{ key: "actions", render: (_: unknown, r: Row) => (
      <Button size="small" onClick={() => markLegit(r)}>{t("watchlist.keywords.markLegit")}</Button>
    ) }] : []),
  ];

  return (
    <Drawer open={value !== null} title={t("watchlist.keywords.hitsTitle", { value })} onClose={onClose} width="min(900px, 100vw)" destroyOnHidden>
      <QueryError error={q.error} />
      <Table<Row> rowKey="finding_id" size="small" loading={q.isPending} dataSource={q.data?.items ?? []}
        columns={columns} pagination={paging.config(q.data?.total)} scroll={{ x: 760 }} />
    </Drawer>
  );
}
