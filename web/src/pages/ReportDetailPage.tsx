import { listPagination } from "../components/pagination";
import { Card, Descriptions, List, Space, Table, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { useReport } from "../api/hooks";
import { SEVERITY_COLORS, StackedBars } from "../components/charts";
import QueryError from "../components/QueryError";
import { fmtTime } from "../components/format";

type Item = Record<string, unknown>;

function safeUrl(u: unknown): string | null {
  return typeof u === "string" && /^https?:\/\//i.test(u) ? u : null;
}

/** 报告详情（设计文档 13、14）：内容与推送的报告相同；只有平台链接与新闻原文可点击，域名只作为文本显示。 */
export default function ReportDetailPage() {
  const { t } = useTranslation();
  const id = Number(useParams().id);
  const q = useReport(id);
  if (q.error) return <QueryError error={q.error} />;
  if (!q.data) return <Card loading />;
  const r = q.data;
  const c = r.content as Item;
  const list = (key: string): Item[] => (Array.isArray(c[key]) ? (c[key] as Item[]) : []);
  const cat = (x: unknown) => t(`category.${String(x)}`, { defaultValue: String(x) });
  const sev = (x: unknown) => <Tag>{t(`severity.${String(x)}`, { defaultValue: String(x) })}</Tag>;
  const open = (x: Item) =>
    typeof x.alert_id === "number" ? <Link to={`/alerts/${x.alert_id}`}>{t("reports.openAlert")}</Link> : null;
  const weekly = c.kind === "weekly";
  const monthly = c.kind === "monthly";
  const previous = (c.previous ?? {}) as Record<string, number>;
  const counts = (c.counts ?? {}) as { news?: number; vulnerabilities?: number };
  const trend = list("trend");
  const sevs = ["critical", "high", "medium"] as const;
  // 月报的概况与上月对比；日报、周报只显示本期数字
  const total = (key: string) => {
    const now = r.totals[key] ?? 0;
    if (!monthly) return now;
    const prev = previous[key] ?? 0;
    return t("reports.compare", { now, prev, delta: now === prev ? "0" : `${now > prev ? "+" : ""}${now - prev}` });
  };
  const status = (a: Item) => {
    let s = t(`alertStatus.${String(a.status)}`, { defaultValue: String(a.status) });
    if (a.verdict) s = t("reports.withVerdict", { status: s, verdict: t(`verdict.${String(a.verdict)}`, { defaultValue: String(a.verdict) }) });
    if (a.takedown) s = t("reports.withTakedown", { status: s, state: t(`takedownState.${String(a.takedown)}`, { defaultValue: String(a.takedown) }) });
    return s;
  };
  const low = (c.low ?? {}) as { count?: number; top?: Item[] };
  const triage = (c.triage ?? {}) as Record<string, number>;
  const takedowns = (c.takedowns ?? {}) as { opened?: number; resolved?: number };
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Card
        title={r.title}
        extra={
          <a href={`/api/v1/reports/${r.id}/html`} download>
            {t("reports.download")}
          </a>
        }
      >
        <Descriptions
          column={{ xs: 1, md: 3 }}
          items={[
            { key: "period", label: t("reports.period"), children: `${fmtTime(r.period_start)} – ${fmtTime(r.period_end)}` },
            { key: "findings", label: t("reports.findings"), children: total("findings") },
            { key: "alerts", label: t("reports.alerts"), children: total("alerts") },
            ...sevs.map((s) => ({ key: s, label: t(`severity.${s}`), children: total(s) })),
            ...(monthly ? [] : [{ key: "low", label: t("reports.lowFindings"), children: r.totals.low ?? 0 }]),
          ]}
        />
      </Card>
      {monthly && (
        <Card title={t("reports.trend")}>
          <StackedBars
            label={t("reports.trend")}
            height={120}
            data={trend.map((m) => ({ ...(m as Record<string, number | string>), day: String(m.month) }))}
            series={sevs.map((k) => ({ key: k, color: SEVERITY_COLORS[k] }))}
          />
          <Table
            size="small"
            pagination={listPagination}
            rowKey={(m) => String(m.month)}
            dataSource={trend}
            columns={[
              { title: t("reports.month"), dataIndex: "month" },
              ...sevs.map((s) => ({ title: t(`severity.${s}`), dataIndex: s })),
            ]}
          />
        </Card>
      )}
      <Card title={t("reports.byCategory")}>
        <Table
          size="small"
          pagination={listPagination}
          rowKey={(x) => String(x.category)}
          dataSource={list("by_category")}
          columns={[
            { title: t("reports.category"), dataIndex: "category", render: (v: unknown) => cat(v) },
            ...(monthly
              ? [
                  { title: t("reports.alertsThisMonth"), dataIndex: "alerts" },
                  { title: t("reports.alertsLastMonth"), dataIndex: "previous" },
                ]
              : [
                  { title: t("reports.findings"), dataIndex: "findings" },
                  { title: t("reports.alerts"), dataIndex: "alerts" },
                ]),
          ]}
        />
      </Card>
      <Card title={t(monthly ? "reports.events" : weekly ? "reports.alertsWeekly" : "reports.alertsDaily")}>
        <List pagination={listPagination}
          size="small"
          dataSource={list("alerts")}
          locale={{ emptyText: t("common.none") }}
          renderItem={(a) => (
            <List.Item key={String(a.alert_id)} extra={open(a)}>
              <Space wrap>
                {sev(a.severity)}
                <span>{cat(a.category)}</span>
                <Typography.Text>{String(a.subject ?? "")}</Typography.Text>
                <Typography.Text type="secondary">{String(a.score ?? "")}</Typography.Text>
                {monthly && <Tag>{status(a)}</Tag>}
              </Space>
            </List.Item>
          )}
        />
      </Card>
      <Card title={monthly ? t("reports.vulnerabilitiesMonthly", { n: counts.vulnerabilities ?? 0 }) : t("reports.vulnerabilities")}>
        <List pagination={listPagination}
          size="small"
          dataSource={list("vulnerabilities")}
          locale={{ emptyText: t("common.none") }}
          renderItem={(v) => (
            <List.Item key={String(v.finding_id)} extra={open(v)}>
              <Space wrap>
                {sev(v.severity)}
                <strong>{String(v.cve ?? "")}</strong>
                <span>{String(v.name ?? "")}</span>
                <Typography.Text type="secondary">{(Array.isArray(v.software) ? v.software : []).join(", ")}</Typography.Text>
              </Space>
            </List.Item>
          )}
        />
      </Card>
      <Card title={monthly ? t("reports.mentions", { n: counts.news ?? 0 }) : t("reports.news")}>
        <List pagination={listPagination}
          size="small"
          dataSource={list("news")}
          locale={{ emptyText: t("common.none") }}
          renderItem={(n) => {
            const url = safeUrl(n.url);
            return (
              <List.Item key={String(n.finding_id)} extra={open(n)}>
                <Space direction="vertical" size={0}>
                  <Space wrap>
                    <Tag>{cat(n.category)}</Tag>
                    {url ? (
                      <a href={url} target="_blank" rel="noopener noreferrer">
                        {String(n.title || url)}
                      </a>
                    ) : (
                      <span>{String(n.title ?? "")}</span>
                    )}
                    <Typography.Text type="secondary">{String(n.source ?? "")}</Typography.Text>
                  </Space>
                  {n.summary ? <Typography.Text type="secondary">{String(n.summary)}</Typography.Text> : null}
                </Space>
              </List.Item>
            );
          }}
        />
      </Card>
      {weekly && (
        <Card title={t("reports.weeklyExtras")}>
          <Descriptions
            column={1}
            items={[
              { key: "low", label: t("reports.lowFindings"), children: low.count ?? 0 },
              {
                key: "triage",
                label: t("reports.triage"),
                children: Object.entries(triage).map(([k, n]) => `${t(`verdict.${k}`, { defaultValue: k })}: ${n}`).join(" · ") || t("common.none"),
              },
              { key: "takedowns", label: t("reports.takedowns"), children: t("reports.takedownLine", { opened: takedowns.opened ?? 0, resolved: takedowns.resolved ?? 0 }) },
            ]}
          />
          <List pagination={listPagination} size="small" dataSource={low.top ?? []} renderItem={(x) => <List.Item key={String(x.finding_id)}>{`${cat(x.category)} · ${String(x.subject ?? "")}`}</List.Item>} />
        </Card>
      )}
    </Space>
  );
}
