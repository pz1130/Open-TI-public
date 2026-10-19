import { Space, Statistic, Table, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import type { Schemas } from "../../api/client";
import { useDashboard } from "../../api/hooks";
import { BarList, SEVERITY_COLORS as COLORS, StackedBars } from "../../components/charts";
import { fmtTime } from "../../components/format";
import { SeverityTag } from "../../components/tags";
import { RollingNumber } from "../../shell/motion";
import { DEFAULT_LIMIT } from "../catalog";
import { Loaded, limitOf, numParam, strParam, type WidgetProps } from "./common";

type Brief = Schemas["AlertBrief"];
type Dashboard = Schemas["DashboardOut"];

/** 依赖 /dashboard 的卡片：category、limit 只有声明了的卡片才传给后端，其余卡片共用同一次请求。 */
function useOverview({ widget, days }: WidgetProps, opts: { category?: boolean; limit?: boolean } = {}) {
  return useDashboard({
    days: numParam(widget, "days") ?? days,
    category: opts.category ? strParam(widget, "category") : null,
    limit: opts.limit ? limitOf(widget) : DEFAULT_LIMIT,
  });
}

function metricValue(d: Dashboard, metric: string): number | null {
  if (metric === "mttr") return d.mttr_hours;
  if (metric === "new_alerts") return d.new_alerts;
  if (metric === "new_findings") return d.new_findings;
  return d.open_alerts[metric.replace(/^open_/, "")] ?? 0;
}

export function StatWidget(p: WidgetProps) {
  const { t } = useTranslation();
  const q = useOverview(p);
  const metric = String(p.widget.params.metric);
  return (
    <Loaded q={q}>
      {(d) => {
        const v = metricValue(d, metric);
        return (
          <Statistic
            className={`oti-stat oti-stat-${metric}`}
            value={v ?? "—"}
            formatter={(val) => <RollingNumber value={val} />}
            suffix={metric === "mttr" && v != null ? t("dashboard.hours") : undefined}
          />
        );
      }}
    </Loaded>
  );
}

export function TrendWidget(p: WidgetProps) {
  const { t } = useTranslation();
  const q = useOverview(p, { category: true });
  return (
    <Loaded q={q}>
      {(d) => (
        <>
          <StackedBars label={t("dashboard.widget.trend")} data={d.trend} series={(["critical", "high", "medium", "low"] as const).map((k) => ({ key: k, color: COLORS[k] }))} />
          <Typography.Text type="secondary">{`${d.trend[0]?.day ?? ""} – ${d.trend[d.trend.length - 1]?.day ?? ""}`}</Typography.Text>
        </>
      )}
    </Loaded>
  );
}

export function MttdWidget(p: WidgetProps) {
  const { t } = useTranslation();
  const q = useOverview(p);
  return (
    <Loaded q={q}>
      {(d) => (
        <Space direction="vertical">
          {d.mttd.map((m) => (
            <div key={m.source}>
              <Typography.Text strong>{t(`dashboard.source.${m.source}`, { defaultValue: m.source })}</Typography.Text>
              <div>{m.median_hours != null ? t("dashboard.median", { hours: m.median_hours, n: m.count }) : t("dashboard.noData")}</div>
              {m.within_target != null && (
                <Tag color={m.within_target >= 0.9 ? "green" : "orange"}>
                  {t("dashboard.withinTarget", { pct: Math.round(m.within_target * 100), target: m.target_hours })}
                </Tag>
              )}
            </div>
          ))}
          <Typography.Text type="secondary">{t("dashboard.mttdNote")}</Typography.Text>
        </Space>
      )}
    </Loaded>
  );
}

type RankField = "by_category" | "by_source" | "hosting_countries" | "hosting_networks";

/** 排行类卡片：条数在前端截取，不影响共用的请求。 */
function rankWidget(field: RankField) {
  return function RankWidget(p: WidgetProps) {
    const { t } = useTranslation();
    const q = useOverview(p);
    const label = (name: string) => (field === "by_category" ? t(`category.${name}`, { defaultValue: name }) : name);
    return (
      <Loaded q={q}>
        {(d) => <BarList items={d[field].slice(0, limitOf(p.widget)).map((c) => ({ ...c, label: label(c.name) }))} empty={t("dashboard.noData")} />}
      </Loaded>
    );
  };
}

export const ByCategoryWidget = rankWidget("by_category");
export const BySourceWidget = rankWidget("by_source");
export const CountriesWidget = rankWidget("hosting_countries");
export const NetworksWidget = rankWidget("hosting_networks");

function alertColumns(t: (k: string, o?: Record<string, unknown>) => string, extra: "score" | "overdue") {
  return [
    {
      title: t("dashboard.alert"),
      dataIndex: "alert_id",
      render: (id: number, r: Brief) => (
        <Space>
          <SeverityTag value={r.severity} />
          <Link to={`/alerts/${id}`}>{`#${id}`}</Link>
        </Space>
      ),
    },
    { title: t("dashboard.category"), dataIndex: "category", render: (c: string) => t(`category.${c}`, { defaultValue: c }) },
    { title: t("dashboard.subject"), dataIndex: "subject", render: (s: string) => <Typography.Text>{s}</Typography.Text> },
    extra === "score"
      ? { title: t("dashboard.score"), dataIndex: "score" }
      : { title: t("dashboard.overdue"), dataIndex: "overdue_hours", render: (h: number) => t("dashboard.overdueHours", { hours: h }) },
  ];
}

export function OverdueWidget(p: WidgetProps) {
  const { t } = useTranslation();
  const q = useOverview(p, { category: true, limit: true });
  return (
    <Loaded q={q}>
      {(d) => (
        <>
          <Typography.Text type="secondary">{t("dashboard.overdueTotal", { n: Object.values(d.overdue).reduce((a, b) => a + b, 0) })}</Typography.Text>
          <Table size="small" pagination={false} rowKey="alert_id" dataSource={d.overdue_alerts} columns={alertColumns(t, "overdue")} locale={{ emptyText: t("dashboard.noData") }} />
        </>
      )}
    </Loaded>
  );
}

export function TopWidget(p: WidgetProps) {
  const { t } = useTranslation();
  const q = useOverview(p, { category: true, limit: true });
  return (
    <Loaded q={q}>
      {(d) => (
        <>
          <Table size="small" pagination={false} rowKey="alert_id" dataSource={d.top_alerts} columns={alertColumns(t, "score")} locale={{ emptyText: t("dashboard.noData") }} />
          <Typography.Text type="secondary">{t("dashboard.generatedAt", { time: fmtTime(d.generated_at) })}</Typography.Text>
        </>
      )}
    </Loaded>
  );
}
