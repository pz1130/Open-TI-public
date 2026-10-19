import { usePagination } from "../components/pagination";
import { Alert, Button, Card, Descriptions, Drawer, Input, Select, Space, Spin, Statistic, Table, Tag, Timeline, Typography } from "antd";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { errorMessage, type Schemas } from "../api/client";
import { takedownEmlUrl, useEditTakedown, useMe, useTakedown, useTakedownStats, useTakedowns, useTransitionTakedown } from "../api/hooks";
import { can } from "../auth/perms";
import DomainText from "../components/DomainText";
import QueryError from "../components/QueryError";
import { fmtTime } from "../components/format";
import { TakedownStateTag } from "../components/tags";

const STATES = ["draft", "approved", "submitted", "acknowledged", "removed", "rejected", "cancelled", "reappeared"];
type To = Schemas["TakedownTransition"]["to"];

function TakedownDetailView({ id }: { id: number }) {
  const { t } = useTranslation();
  const me = useMe().data;
  const q = useTakedown(id);
  const edit = useEditTakedown(id);
  const move = useTransitionTakedown(id);
  const [draft, setDraft] = useState<{ subject: string; body: string } | null>(null);
  const [note, setNote] = useState("");
  const [externalRef, setExternalRef] = useState("");
  if (q.isPending) return <Spin />;
  if (q.isError) return <QueryError error={q.error} />;
  const { takedown: td, events, escalation } = q.data;
  const canDraft = can(me, "takedown:draft");
  const editable = canDraft && (td.state === "draft" || td.state === "approved");
  const subject = draft?.subject ?? td.subject;
  const body = draft?.body ?? td.body;
  const go = (to: To) =>
    move.mutate(
      { to, note, external_ref: externalRef.trim() || null },
      {
        onSuccess: () => {
          setNote("");
          setExternalRef("");
        },
      },
    );
  const actions: ReactNode[] = [];
  if (td.state === "draft" && can(me, "takedown:approve") && td.created_by !== me?.username) {
    actions.push(<Button key="approve" type="primary" onClick={() => go("approved")}>{t("takedown.action.approve")}</Button>);
  }
  if (canDraft) {
    if (td.state === "approved") {
      if (td.target.email) actions.push(<Button key="eml" href={takedownEmlUrl(td.id)}>{t("takedown.action.eml")}</Button>);
      if (td.target.url) {
        actions.push(
          <Button key="form" href={td.target.url} target="_blank" rel="noopener noreferrer">
            {t("takedown.action.openForm")}
          </Button>,
        );
      }
      actions.push(<Button key="submitted" type="primary" onClick={() => go("submitted")}>{t("takedown.action.submitted")}</Button>);
      actions.push(<Button key="draft" onClick={() => go("draft")}>{t("takedown.action.backToDraft")}</Button>);
    }
    if (td.state === "submitted") {
      actions.push(<Button key="ack" onClick={() => go("acknowledged")}>{t("takedown.action.acknowledged")}</Button>);
    }
    if (td.state === "submitted" || td.state === "acknowledged") {
      actions.push(<Button key="removed" type="primary" onClick={() => go("removed")}>{t("takedown.action.removed")}</Button>);
      actions.push(<Button key="rejected" danger onClick={() => go("rejected")}>{t("takedown.action.rejected")}</Button>);
    }
    if (td.state === "draft" || td.state === "approved") {
      actions.push(<Button key="cancel" danger onClick={() => go("cancelled")}>{t("takedown.action.cancel")}</Button>);
    }
  }
  const error = edit.error ?? move.error;
  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {error && <Alert type="error" showIcon message={t("common.error", { message: errorMessage(error) })} />}
      {td.state === "draft" && td.created_by === me?.username && <Alert type="info" showIcon message={t("takedown.fourEyes")} />}
      <Descriptions
        column={1}
        size="small"
        items={[
          { key: "state", label: t("takedown.col.state"), children: <TakedownStateTag value={td.state} /> },
          {
            key: "target",
            label: t("takedown.col.target"),
            children: `${td.target.name} · ${t(`targetKind.${td.target.kind}`, { defaultValue: td.target.kind })}`,
          },
          { key: "contact", label: t("takedown.contact"), children: td.target.email ?? td.target.url ?? "-" },
          { key: "alert", label: t("takedown.alert"), children: <Link to={`/alerts/${td.alert_id}`}>#{td.alert_id}</Link> },
          { key: "by", label: t("takedown.createdBy"), children: `${td.created_by}${td.approved_by ? ` → ${td.approved_by}` : ""}` },
          { key: "ref", label: t("takedown.externalRef"), children: td.external_ref ?? "-" },
          {
            key: "due",
            label: t("takedown.due"),
            children: td.due_at ? `${fmtTime(td.due_at)} · ${t("takedown.remindersCount", { n: td.reminders })}` : "-",
          },
          ...(td.reappeared_alert_id
            ? [{ key: "re", label: t("takedown.reappeared"), children: <Link to={`/alerts/${td.reappeared_alert_id}`}>#{td.reappeared_alert_id}</Link> }]
            : []),
        ]}
      />
      {td.target.note && <Alert type="warning" showIcon message={td.target.note} />}
      <Input aria-label={t("takedown.subject")} value={subject} disabled={!editable} onChange={(e) => setDraft({ subject: e.target.value, body })} />
      <Input.TextArea
        aria-label={t("takedown.body")}
        value={body}
        disabled={!editable}
        autoSize={{ minRows: 10, maxRows: 24 }}
        onChange={(e) => setDraft({ subject, body: e.target.value })}
      />
      {editable && draft && (
        <Button loading={edit.isPending} onClick={() => edit.mutate({ subject, body }, { onSuccess: () => setDraft(null) })}>
          {td.state === "approved" ? t("takedown.saveAndReset") : t("common.save")}
        </Button>
      )}
      {actions.length > 0 && (
        <>
          <Input aria-label={t("takedown.note")} placeholder={t("takedown.note")} value={note} onChange={(e) => setNote(e.target.value)} />
          {(td.state === "approved" || td.state === "submitted") && (
            <Input
              aria-label={t("takedown.externalRef")}
              placeholder={t("takedown.externalRef")}
              value={externalRef}
              onChange={(e) => setExternalRef(e.target.value)}
            />
          )}
          <Space wrap>{actions}</Space>
        </>
      )}
      {(td.reminders > 0 || td.state === "rejected") && escalation.length > 0 && (
        <Card size="small" title={t("takedown.escalation")}>
          {escalation.map((e) => (
            <div key={e.id}>
              <strong>{e.name}</strong> <Typography.Text copyable>{e.url ?? e.email ?? ""}</Typography.Text>
              {e.note && (
                <div>
                  <Typography.Text type="secondary">{e.note}</Typography.Text>
                </div>
              )}
            </div>
          ))}
        </Card>
      )}
      <Timeline
        items={events.map((e) => ({
          children: `${fmtTime(e.ts)} · ${e.actor} · ${e.from_state ? `${t(`takedownState.${e.from_state}`)} → ` : ""}${t(`takedownState.${e.to_state}`)}${e.note ? ` · ${e.note}` : ""}`,
        }))}
      />
    </Space>
  );
}

export default function TakedownsPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const [state, setState] = useState<string[]>([]);
  const paging = usePagination(state);
  const list = useTakedowns({ state }, paging.page, paging.pageSize);
  const stats = useTakedownStats();
  const selected = Number(params.get("id")) || null;
  const items = list.data?.items ?? [];
  return (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Card title={t("takedown.title")}>
        {stats.data && (
          <Space size="large" wrap>
            <Statistic
              title={t("takedown.mttr")}
              value={stats.data.mttr_hours ?? "-"}
              suffix={stats.data.mttr_hours != null ? t("takedown.hours") : undefined}
            />
            {STATES.map((s) => (
              <Statistic key={s} title={t(`takedownState.${s}`)} value={stats.data.by_state[s] ?? 0} />
            ))}
          </Space>
        )}
      </Card>
      <Card
        extra={
          <Select
            mode="multiple"
            allowClear
            placeholder={t("takedown.filterState")}
            style={{ minWidth: 240 }}
            value={state}
            onChange={setState}
            options={STATES.map((s) => ({ value: s, label: t(`takedownState.${s}`) }))}
          />
        }
      >
        <QueryError error={list.error} />
        <Table<Schemas["TakedownOut"]>
          rowKey="id"
          loading={list.isPending}
          dataSource={items}
          pagination={paging.config(list.data?.total)}
          onRow={(r) => ({ onClick: () => setParams({ id: String(r.id) }), style: { cursor: "pointer" } })}
          columns={[
            { title: "#", dataIndex: "id", width: 80 },
            { title: t("takedown.col.domain"), dataIndex: "domain", render: (v: string) => <DomainText value={v} /> },
            {
              title: t("takedown.col.target"),
              key: "target",
              render: (_: unknown, r) => (
                <Space>
                  <Tag>{t(`targetKind.${r.target.kind}`, { defaultValue: r.target.kind })}</Tag>
                  {r.target.name}
                </Space>
              ),
            },
            { title: t("takedown.col.state"), dataIndex: "state", render: (v: string) => <TakedownStateTag value={v} /> },
            { title: t("takedown.col.updated"), dataIndex: "updated_at", render: (v: string) => fmtTime(v) },
          ]}
        />
      </Card>
      <Drawer
        open={selected !== null}
        width={720}
        destroyOnHidden
        title={selected !== null ? t("takedown.detailTitle", { id: selected }) : ""}
        onClose={() => setParams({})}
      >
        {selected !== null && <TakedownDetailView key={selected} id={selected} />}
      </Drawer>
    </Space>
  );
}
