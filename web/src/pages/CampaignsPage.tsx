import { usePagination } from "../components/pagination";
import { Card, Space, Table, Tabs, Tag, Typography, type TableProps } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { Schemas } from "../api/client";
import { useCampaigns, type CampaignState } from "../api/hooks";
import QueryError from "../components/QueryError";
import { campaignLabel } from "../components/campaign";
import { fmtTime } from "../components/format";
import { SeverityTag } from "../components/tags";

type Row = Schemas["CampaignSummary"];
const STATES: CampaignState[] = ["candidate", "confirmed", "dismissed"];

export default function CampaignsPage() {
  const { t } = useTranslation();
  const [state, setState] = useState<CampaignState>("candidate");
  const paging = usePagination(state);
  const q = useCampaigns(state, paging.page, paging.pageSize);
  const columns: TableProps<Row>["columns"] = [
    { title: t("campaigns.col.name"), key: "name", render: (_: unknown, r: Row) => <Link to={`/campaigns/${r.id}`}>{campaignLabel(t, r)}</Link> },
    {
      title: t("campaigns.col.members"),
      key: "members",
      render: (_: unknown, r: Row) => (
        <Space>
          {r.member_count}
          {r.pending_count > 0 && <Typography.Text type="warning">{t("campaigns.pendingSuffix", { count: r.pending_count })}</Typography.Text>}
        </Space>
      ),
    },
    { title: t("campaigns.col.activeAlerts"), dataIndex: "active_alerts" },
    { title: t("campaigns.col.topSeverity"), dataIndex: "top_severity", render: (v: string | null) => (v ? <SeverityTag value={v} /> : "—") },
    {
      title: t("campaigns.col.signals"),
      dataIndex: "signal_kinds",
      render: (kinds: string[]) => kinds.map((k) => <Tag key={k}>{t(`campaigns.signal.${k}`)}</Tag>),
    },
    { title: t("campaigns.col.updatedAt"), dataIndex: "updated_at", render: (v: string) => fmtTime(v) },
  ];
  return (
    <Card title={t("campaigns.title")}>
      <Typography.Paragraph type="secondary">{t("campaigns.review")}</Typography.Paragraph>
      <Tabs
        activeKey={state}
        onChange={(key) => {
          setState(key as CampaignState);
        }}
        items={STATES.map((s) => ({ key: s, label: t(`campaigns.state.${s}`) }))}
      />
      <QueryError error={q.error} />
      <Table<Row>
        rowKey="id"
        size="middle"
        loading={q.isPending}
        dataSource={q.data?.items ?? []}
        columns={columns}
        locale={{ emptyText: t("campaigns.none") }}
        pagination={paging.config(q.data?.total)}
      />
    </Card>
  );
}
