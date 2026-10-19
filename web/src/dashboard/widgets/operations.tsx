import { List, Space, Statistic, Table, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { Schemas } from "../../api/client";
import { useCampaigns, useConnectors, useMyAlerts, useTakedownStats } from "../../api/hooks";
import { campaignLabel } from "../../components/campaign";
import { fmtTime, fromNow } from "../../components/format";
import { AlertStatusTag, ConnectorHealthTag, SeverityTag, TakedownStateTag } from "../../components/tags";
import { Loaded, limitOf, type WidgetProps } from "./common";

const TAKEDOWN_STATES = ["draft", "approved", "submitted", "acknowledged", "removed", "rejected", "cancelled", "reappeared"];

/** 指派给我的未结告警：严重程度高的在前，同级别先建的在前（服务器排序）。 */
export function MyTodoWidget({ widget }: WidgetProps) {
  const { t } = useTranslation();
  const q = useMyAlerts(limitOf(widget));
  return (
    <Loaded q={q}>
      {(page) => (
        <Table<Schemas["AlertSummary"]>
          size="small"
          pagination={false}
          rowKey="id"
          dataSource={page.items}
          locale={{ emptyText: t("dashboard.noTodo") }}
          columns={[
            { title: t("dashboard.alert"), dataIndex: "id", render: (id: number, r) => <Space><SeverityTag value={r.severity} /><Link to={`/alerts/${id}`}>{`#${id}`}</Link></Space> },
            { title: t("dashboard.subject"), dataIndex: "domain", render: (d: string) => <Typography.Text>{d}</Typography.Text> },
            { title: t("alerts.col.status"), dataIndex: "status", render: (s: string) => <AlertStatusTag value={s} /> },
            { title: t("alerts.col.created"), dataIndex: "created_at", render: (v: string) => fromNow(v) },
          ]}
        />
      )}
    </Loaded>
  );
}

export function TakedownsWidget(_: WidgetProps) {
  const { t } = useTranslation();
  const q = useTakedownStats();
  return (
    <Loaded q={q}>
      {(d) => {
        const states = TAKEDOWN_STATES.filter((s) => (d.by_state[s] ?? 0) > 0);
        const targets = [...d.targets].sort((a, b) => b.total - a.total).slice(0, 5);
        return (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Statistic title={t("takedown.mttr")} value={d.mttr_hours ?? "—"} suffix={d.mttr_hours != null ? t("takedown.hours") : undefined} />
            {states.length === 0 ? (
              <Typography.Text type="secondary">{t("dashboard.noData")}</Typography.Text>
            ) : (
              <Space wrap>
                {states.map((s) => (
                  <span key={s}>
                    <TakedownStateTag value={s} />
                    {d.by_state[s]}
                  </span>
                ))}
              </Space>
            )}
            {targets.length > 0 && (
              <Table<Schemas["TargetStatOut"]>
                size="small"
                pagination={false}
                rowKey={(r) => `${r.kind}:${r.name}`}
                dataSource={targets}
                columns={[
                  { title: t("dashboard.target"), dataIndex: "name" },
                  { title: t("dashboard.targetTotal"), dataIndex: "total" },
                  { title: t("dashboard.targetRemoved"), dataIndex: "removed" },
                ]}
              />
            )}
            <Link to="/takedowns">{t("dashboard.viewAll")}</Link>
          </Space>
        );
      }}
    </Loaded>
  );
}

export function CampaignsWidget({ widget }: WidgetProps) {
  const { t } = useTranslation();
  const candidates = useCampaigns("candidate", 1);
  const confirmed = useCampaigns("confirmed", 1);
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Loaded q={candidates}>
        {(page) => (
          <Link to="/campaigns">
            <Statistic title={t("dashboard.campaignCandidates")} value={page.total} />
          </Link>
        )}
      </Loaded>
      <Loaded q={confirmed}>
        {(page) => (
          <List
            size="small"
            header={t("dashboard.campaignRecent")}
            locale={{ emptyText: t("dashboard.noData") }}
            dataSource={page.items.slice(0, limitOf(widget))}
            renderItem={(c) => (
              <List.Item>
                <Space>
                  {c.top_severity && <SeverityTag value={c.top_severity} />}
                  <Link to={`/campaigns/${c.id}`}>{campaignLabel(t, c)}</Link>
                  <Typography.Text type="secondary">{t("dashboard.campaignActive", { n: c.active_alerts })}</Typography.Text>
                </Space>
              </List.Item>
            )}
          />
        )}
      </Loaded>
    </Space>
  );
}

/** 只列出已启用且不健康（health 不是 ok，或 24 小时内出过错）的连接器。 */
export function ConnectorHealthWidget(_: WidgetProps) {
  const { t } = useTranslation();
  const q = useConnectors();
  return (
    <Loaded q={q}>
      {(all) => {
        const bad = all.filter((c) => c.enabled && (c.health !== "ok" || c.errors_24h > 0));
        return (
          <Space direction="vertical" style={{ width: "100%" }}>
            {bad.length === 0 ? (
              <Typography.Text type="success">{t("dashboard.allHealthy", { n: all.filter((c) => c.enabled).length })}</Typography.Text>
            ) : (
              <List
                size="small"
                dataSource={bad}
                renderItem={(c) => (
                  <List.Item>
                    <Space wrap>
                      <ConnectorHealthTag value={c.health} />
                      <Typography.Text strong>{c.name}</Typography.Text>
                      <Typography.Text type="secondary">
                        {t("dashboard.lastSuccess", { time: c.last_success_at ? fmtTime(c.last_success_at) : t("dashboard.never") })}
                      </Typography.Text>
                      {c.errors_24h > 0 && <Typography.Text type="danger">{t("dashboard.errors24h", { n: c.errors_24h })}</Typography.Text>}
                    </Space>
                  </List.Item>
                )}
              />
            )}
            <Link to="/connectors">{t("dashboard.viewAll")}</Link>
          </Space>
        );
      }}
    </Loaded>
  );
}
