import { usePagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import { Alert, Button, Card, Input, Space, Table, type TableProps } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../api/client";
import { useAuditLogs, useAuditVerify, type AuditFilters } from "../api/hooks";
import JsonBlock from "../components/JsonBlock";
import { fmtTime } from "../components/format";

type Row = Schemas["AuditEntry"];

export default function AuditLogPage() {
  const { t } = useTranslation();
  const [filters, setFilters] = useState<AuditFilters>({});
  const paging = usePagination(filters);
  const q = useAuditLogs(filters, paging.page, paging.pageSize);
  const verify = useAuditVerify();
  const rows = q.data?.items ?? [];
  const columns: TableProps<Row>["columns"] = [
    { title: t("audit.ts"), dataIndex: "ts", width: 170, render: (v: string) => fmtTime(v) },
    { title: t("audit.actor"), dataIndex: "actor" },
    { title: t("audit.action"), dataIndex: "action" },
    {
      title: t("audit.target"),
      key: "target",
      render: (_: unknown, r: Row) => (r.target_type ? `${r.target_type}#${r.target_id ?? ""}` : null),
    },
    { title: t("audit.ip"), dataIndex: "ip" },
  ];
  return (
    <Card
      title={t("audit.title")}
      extra={<Button onClick={() => verify.mutate()} loading={verify.isPending}>{t("audit.verify")}</Button>}
    >
      <QueryError error={verify.error} />
      {verify.data && (
        <Alert
          style={{ marginBottom: 16 }}
          showIcon
          type={verify.data.ok ? "success" : "error"}
          message={verify.data.ok ? t("audit.verifyOk") : t("audit.verifyBroken", { id: verify.data.first_broken_id })}
        />
      )}
      <QueryError error={q.error} />
      <Space wrap style={{ marginBottom: 16 }}>
        <Input.Search allowClear placeholder={t("audit.filterActor")} style={{ width: 200 }}
          onSearch={(v) => setFilters({ ...filters, actor: v.trim() || undefined })} />
        <Input.Search allowClear placeholder={t("audit.filterAction")} style={{ width: 200 }}
          onSearch={(v) => setFilters({ ...filters, action: v.trim() || undefined })} />
      </Space>
      <Table<Row>
        rowKey="id"
        size="small"
        loading={q.isPending}
        dataSource={rows}
        columns={columns}
        pagination={paging.config(q.data?.total)}
        expandable={{ expandedRowRender: (r) => <JsonBlock value={r.detail} /> }}
      />
    </Card>
  );
}
