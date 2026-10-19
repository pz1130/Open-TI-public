import { usePagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import { CameraOutlined } from "@ant-design/icons";
import { App, Button, Card, Input, Select, Space, Table, Tag, Typography, type TableProps } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { errorMessage, type Schemas } from "../api/client";
import { useAlerts, useIgnoreAlert, useMe, type AlertFilters } from "../api/hooks";
import { can } from "../auth/perms";
import DomainText from "../components/DomainText";
import AttackTags from "../components/AttackTags";
import { fmtTime } from "../components/format";
import { AlertStatusTag, SeverityTag } from "../components/tags";
import SubmitLeadModal from "../components/SubmitLeadModal";

type Row = Schemas["AlertSummary"];
const STATUSES = ["open", "acknowledged", "closed", "superseded"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CATEGORIES = ["phishing_site", "typosquat_domain", "unapproved_certificate", "certificate_expiry", "reported_phishing", "clone_site", "email_spoofing", "fraud_scam", "impersonation_account"];

export default function AlertQueuePage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const me = useMe().data;
  const { message } = App.useApp();
  const ignore = useIgnoreAlert();
  const [submitOpen, setSubmitOpen] = useState(false);
  const [filters, setFilters] = useState<AlertFilters>({ status: ["open", "acknowledged"], severity: [] });
  const paging = usePagination(filters);
  const q = useAlerts(filters, paging.page, paging.pageSize);
  const rows = q.data?.items ?? [];
  const columns: TableProps<Row>["columns"] = [
    { title: t("alerts.col.severity"), dataIndex: "severity", width: 90, render: (v: string) => <SeverityTag value={v} /> },
    { title: t("alerts.col.domain"), dataIndex: "domain", render: (v: string) => <DomainText value={v} /> },
    { title: t("alerts.col.category"), dataIndex: "category", render: (v: string) => t(`category.${v}`, { defaultValue: v }) },
    { title: t("attack.candidates"), dataIndex: "attack_techniques", render: (v: Row["attack_techniques"]) => <AttackTags techniques={v} /> },
    { title: t("alerts.col.score"), dataIndex: "score", width: 70, align: "right" },
    {
      title: t("alerts.col.reasons"),
      dataIndex: "reasons",
      render: (v: string[]) => v.map((r) => <Tag key={r}>{t(`reason.${r}`, { defaultValue: r })}</Tag>),
    },
    { title: t("alerts.col.status"), dataIndex: "status", width: 150, render: (v: string, row) => <Space wrap><AlertStatusTag value={v} />{row.ignored && <Tag>{t("alerts.ignoredTag")}</Tag>}</Space> },
    {
      title: t("alerts.col.evidence"),
      key: "evidence",
      width: 100,
      render: (_: unknown, r: Row) =>
        r.screenshot_id ? <CameraOutlined aria-label={t("detail.screenshot")} /> : t(`evidenceStatus.${r.evidence_status}`),
    },
    { title: t("alerts.col.created"), dataIndex: "created_at", width: 170, render: (v: string) => fmtTime(v) },
    {
      // 域名单元格只能复制、不跳转；给新操作员一个显式入口，整行点击仍然有效
      key: "open",
      width: 160,
      render: (_: unknown, r: Row) => (
        <Space><Button
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            navigate(`/alerts/${r.id}`);
          }}
        >
          {t("alerts.open")}
        </Button>
          {can(me, "alerts:triage") && ["open", "acknowledged"].includes(r.status) && <Button
            size="small" loading={ignore.isPending && ignore.variables?.id === r.id}
            onClick={(e) => {
              e.stopPropagation();
              ignore.mutate({ id: r.id, ignored: !r.ignored }, {
                onError: (error) => void message.error(t("common.error", { message: errorMessage(error) })),
              });
            }}
          >{t(r.ignored ? "alerts.restore" : "alerts.ignore")}</Button>}
        </Space>
      ),
    },
  ];
  return (
    <Card
      title={t("alerts.title")}
      extra={can(me, "alerts:triage") && <Button type="primary" onClick={() => setSubmitOpen(true)}>{t("submit.open")}</Button>}
    >
      <QueryError error={q.error} />
      <Typography.Paragraph type="secondary">{t("alerts.ignoreHint")}</Typography.Paragraph>
      <Space wrap style={{ marginBottom: 16 }}>
        <Select aria-label={t("alerts.ignoreFilter")} value={filters.ignored ?? "exclude"} style={{ minWidth: 160 }}
          options={["exclude", "only", "all"].map((v) => ({ value: v, label: t(`alerts.ignoreView.${v}`) }))}
          onChange={(ignored: "exclude" | "only" | "all") => setFilters({ ...filters, ignored })} />
        <Select
          mode="multiple" allowClear style={{ minWidth: 220 }} placeholder={t("alerts.filter.status")}
          value={filters.status}
          options={STATUSES.map((s) => ({ value: s, label: t(`alertStatus.${s}`) }))}
          onChange={(status: string[]) => setFilters({ ...filters, status })}
        />
        <Select
          mode="multiple" allowClear style={{ minWidth: 200 }} placeholder={t("alerts.filter.severity")}
          value={filters.severity}
          options={SEVERITIES.map((s) => ({ value: s, label: t(`severity.${s}`) }))}
          onChange={(severity: string[]) => setFilters({ ...filters, severity })}
        />
        <Select
          allowClear style={{ minWidth: 180 }} placeholder={t("alerts.filter.category")}
          value={filters.category}
          options={CATEGORIES.map((c) => ({ value: c, label: t(`category.${c}`) }))}
          onChange={(category?: string) => setFilters({ ...filters, category })}
        />
        <Input.Search
          allowClear style={{ width: 240 }} placeholder={t("alerts.filter.search")}
          onSearch={(value) => setFilters({ ...filters, q: value.trim() || undefined })}
        />
      </Space>
      <Table<Row>
        rowKey="id"
        size="middle"
        loading={q.isPending}
        dataSource={rows}
        columns={columns}
        pagination={paging.config(q.data?.total)}
        onRow={(r) => ({ onClick: () => navigate(`/alerts/${r.id}`), style: { cursor: "pointer" } })}
      />
      <SubmitLeadModal open={submitOpen} onClose={() => setSubmitOpen(false)} />
    </Card>
  );
}
