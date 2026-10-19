import { usePagination } from "../components/pagination";
import { Button, Card, Descriptions, Input, Select, Space, Table, Tag, Typography } from "antd";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../api/client";
import { useConnectors, useMe } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import { fmtTime } from "../components/format";
import { ConnectorHealthTag } from "../components/tags";
import ConnectorEditor from "./ConnectorEditor";

type Connector = Schemas["ConnectorOut"];
const HEALTH = ["ok", "failing", "stale", "never", "disabled", "blocked", "unknown", "n/a"];

function safeUrl(u: string | null | undefined): string | null {
  return u && /^https?:\/\//i.test(u) ? u : null;
}

function Details({ c }: { c: Connector }) {
  const { t } = useTranslation();
  const home = safeUrl(c.homepage);
  const tos = safeUrl(c.tos_url);
  const credState = (x: Connector["credentials"][number]) =>
    x.problem ? t("connectors.credProblem") : x.configured === null ? t("connectors.credNode") : x.configured ? t("connectors.credSet") : t("connectors.credUnset");
  return (
    <Descriptions
      size="small"
      column={1}
      items={[
        { key: "reason", label: t("connectors.reason"), children: c.reason || "—" },
        { key: "location", label: t("connectors.location"), children: c.location },
        { key: "egress", label: t("connectors.egress"), children: c.egress },
        { key: "schedule", label: t("connectors.schedule"), children: c.schedule ?? "—" },
        {
          key: "credentials",
          label: t("connectors.credentials"),
          children: c.credentials.length
            ? c.credentials.map((x) => (
                <Tag key={x.name} color={x.problem ? "red" : x.configured === null ? "purple" : x.configured ? "green" : x.required ? "red" : "default"}>
                  {`${x.name}：${credState(x)}`}
                </Tag>
              ))
            : "—",
        },
        { key: "commercial", label: t("connectors.commercial"), children: t(`connectors.commercialUse.${c.commercial_use}`, { defaultValue: c.commercial_use }) },
        {
          key: "links",
          label: t("connectors.links"),
          children: (
            <Space>
              {home && (
                <a href={home} target="_blank" rel="noopener noreferrer">
                  {t("connectors.homepage")}
                </a>
              )}
              {tos && (
                <a href={tos} target="_blank" rel="noopener noreferrer">
                  {t("connectors.tos")}
                </a>
              )}
            </Space>
          ),
        },
        { key: "notes", label: t("connectors.notes"), children: <Typography.Text style={{ whiteSpace: "pre-wrap" }}>{c.compliance_notes || "—"}</Typography.Text> },
        { key: "message", label: t("connectors.lastMessage"), children: c.last_run?.message || "—" },
        { key: "success", label: t("connectors.lastSuccess"), children: c.last_success_at ? fmtTime(c.last_success_at) : "—" },
      ]}
    />
  );
}

export default function ConnectorsPage() {
  const { t } = useTranslation();
  const q = useConnectors();
  const me = useMe();
  const canWrite = can(me.data, "connectors:write");
  const canApprove = can(me.data, "connectors:approve");
  const [editing, setEditing] = useState<Connector | null>(null);
  const [text, setText] = useState("");
  const [health, setHealth] = useState<string | undefined>();
  const paging = usePagination([text, health]);
  const rows = useMemo(
    () =>
      (q.data ?? []).filter(
        (c) => (!health || c.health === health) && (!text || `${c.id} ${c.name}`.toLowerCase().includes(text.toLowerCase())),
      ),
    [q.data, text, health],
  );
  return (
    <Card
      title={t("connectors.title")}
      extra={
        <Space>
          <Input.Search allowClear placeholder={t("connectors.search")} onSearch={(v) => setText(v.trim())} />
          <Select
            allowClear
            style={{ width: 140 }}
            placeholder={t("connectors.filterHealth")}
            value={health}
            onChange={setHealth}
            options={HEALTH.map((h) => ({ value: h, label: t(`connectors.health.${h}`) }))}
          />
        </Space>
      }
    >
      <QueryError error={q.error} />
      <Typography.Paragraph type="secondary">{t(canWrite || canApprove ? "connectors.editHint" : "connectors.readonly")}</Typography.Paragraph>
      <Table
        size="small"
        rowKey="id"
        loading={q.isPending}
        dataSource={rows}
        pagination={paging.config(q.data ? rows.length : undefined)}
        expandable={{ expandedRowRender: (c) => <Details c={c} /> }}
        columns={[
          {
            title: t("connectors.name"),
            dataIndex: "name",
            render: (_: string, c: Connector) => (
              <Space direction="vertical" size={0}>
                <span>{c.name}</span>
                <Typography.Text type="secondary" code>
                  {c.id}
                </Typography.Text>
              </Space>
            ),
          },
          { title: t("connectors.category"), dataIndex: "category" },
          {
            title: t("connectors.tier"),
            dataIndex: "tier",
            render: (v: string) => <Tag color={v === "free" ? "green" : v === "paid" ? "red" : "blue"}>{t(`connectors.tierName.${v}`, { defaultValue: v })}</Tag>,
          },
          {
            title: t("connectors.license"),
            dataIndex: "license_approved",
            render: (v: boolean, c: Connector) =>
              v ? <Tag color="green">{`${t("connectors.approved")}${c.license_ref ? ` · ${c.license_ref}` : ""}`}</Tag> : <Tag>{t("connectors.notApproved")}</Tag>,
          },
          {
            title: t("connectors.healthTitle"),
            dataIndex: "health",
            render: (h: string, c: Connector) => <Space direction="vertical" size={0}>
              <ConnectorHealthTag value={h} />
              {c.runnable === false && <Typography.Text type="secondary">{c.reason}</Typography.Text>}
            </Space>,
          },
          {
            title: t("connectors.lastRun"),
            dataIndex: "last_run",
            render: (r: Connector["last_run"]) => (r ? `${fmtTime(r.started_at)} · ${t("connectors.items", { n: r.items })}` : "—"),
          },
          {
            title: t("connectors.day"),
            key: "day",
            render: (_: unknown, c: Connector) => t("connectors.dayValue", { runs: c.runs_24h, errors: c.errors_24h }),
          },
          ...(canWrite || canApprove ? [{
            title: t("connectors.actions"),
            key: "actions",
            render: (_: unknown, c: Connector) => <Button size="small" onClick={() => setEditing(c)}>{t("connectors.configure")}</Button>,
          }] : []),
        ]}
      />
      <ConnectorEditor id={editing?.id ?? null} name={editing?.name ?? ""} canWrite={canWrite} canApprove={canApprove} onClose={() => setEditing(null)} />
    </Card>
  );
}
