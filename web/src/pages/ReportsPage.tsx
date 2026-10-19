import { usePagination } from "../components/pagination";
import { Card, List, Pagination, Segmented, Space, Tag, Typography } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { type ReportKind, useReports } from "../api/hooks";
import QueryError from "../components/QueryError";
import { fmtTime } from "../components/format";

export default function ReportsPage() {
  const { t } = useTranslation();
  const [kind, setKind] = useState<ReportKind>("");
  const paging = usePagination(kind);
  const list = useReports(kind, paging.page, paging.pageSize);
  const items = list.data?.items ?? [];
  return (
    <Card
      title={t("reports.title")}
      extra={
        <Segmented
          value={kind}
          onChange={(v) => setKind(v as ReportKind)}
          options={[
            { value: "", label: t("common.all") },
            { value: "daily", label: t("reports.kind.daily") },
            { value: "weekly", label: t("reports.kind.weekly") },
            { value: "monthly", label: t("reports.kind.monthly") },
          ]}
        />
      }
    >
      <QueryError error={list.error} />
      <List
        loading={list.isPending}
        dataSource={items}
        locale={{ emptyText: t("reports.empty") }}
        renderItem={(r) => (
          <List.Item key={r.id} extra={r.sent_at ? <Tag color="green">{t("reports.sent")}</Tag> : <Tag>{t("reports.unsent")}</Tag>}>
            <Space direction="vertical" size={0}>
              <Link to={`/reports/${r.id}`}>{r.title}</Link>
              <Typography.Text type="secondary">
                {t("reports.line", {
                  from: fmtTime(r.period_start),
                  to: fmtTime(r.period_end),
                  findings: r.totals.findings ?? 0,
                  alerts: r.totals.alerts ?? 0,
                })}
              </Typography.Text>
            </Space>
          </List.Item>
        )}
      />
      <Pagination {...paging.config(list.data?.total)} />
    </Card>
  );
}
