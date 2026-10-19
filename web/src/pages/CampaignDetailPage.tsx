import { listPagination } from "../components/pagination";
import { Alert, App, Button, Card, Descriptions, Form, Input, Modal, Popconfirm, Radio, Result, Space, Spin, Table, Tag, Typography, type TableProps } from "antd";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";
import { errorMessage, type Schemas } from "../api/client";
import { useCampaign, useCampaignBulk, useDecideMember, useMe, useUpdateCampaign } from "../api/hooks";
import { can } from "../auth/perms";
import DomainText from "../components/DomainText";
import { campaignLabel } from "../components/campaign";
import { fmtTime } from "../components/format";
import { AlertStatusTag, SeverityTag } from "../components/tags";

type Member = Schemas["CampaignMemberOut"];
type BulkAction = "verdict" | "acknowledge" | "close";
const VERDICTS = ["true_positive", "false_positive", "benign_known", "duplicate", "out_of_scope"] as const;
const ACTIVE = new Set(["open", "acknowledged"]);

export default function CampaignDetailPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const navigate = useNavigate();
  const id = Number(useParams().id);
  const me = useMe().data;
  const q = useCampaign(id);
  const update = useUpdateCampaign(id);
  const decide = useDecideMember(id);
  const bulk = useCampaignBulk(id);
  const [bulkAction, setBulkAction] = useState<BulkAction | null>(null);
  const [bulkForm] = Form.useForm<{ verdict?: string; reason?: string }>();
  const [infoForm] = Form.useForm<{ name: string; note: string }>();
  if (q.isPending) return <Spin />;
  if (q.isError) return <Result status="error" title={errorMessage(q.error)} />;
  const d = q.data;
  const c = d.campaign;
  const canTriage = can(me, "alerts:triage");
  const confirmed = c.state === "confirmed";
  const onError = (e: unknown) => void message.error(t("common.error", { message: errorMessage(e) }));
  const valueOf = new Map(d.members.map((m) => [m.finding_id, m.value]));
  const members = d.members.filter((m) => m.state === "member");
  const pending = d.members.filter((m) => m.state === "pending");
  const excluded = d.members.filter((m) => m.state === "excluded");
  const affected = members.filter((m) => m.status && ACTIVE.has(m.status) && !(bulkAction === "acknowledge" && m.status === "acknowledged")).length;

  const columns = (actions: (m: Member) => ReactNode): TableProps<Member>["columns"] => [
    {
      title: t("campaigns.memberCol.value"),
      key: "value",
      render: (_: unknown, m: Member) => (m.alert_id ? <Link to={`/alerts/${m.alert_id}`}><DomainText value={m.value} /></Link> : <DomainText value={m.value} />),
    },
    { title: t("campaigns.memberCol.severity"), dataIndex: "severity", render: (v: string | null) => (v ? <SeverityTag value={v} /> : "—") },
    { title: t("campaigns.memberCol.status"), dataIndex: "status", render: (v: string | null) => (v ? <AlertStatusTag value={v} /> : "—") },
    { title: t("campaigns.memberCol.assignee"), dataIndex: "assignee", render: (v: string | null) => v ?? "—" },
    { title: t("campaigns.memberCol.verdict"), dataIndex: "verdict", render: (v: string | null) => (v ? t(`verdict.${v}`, { defaultValue: v }) : "—") },
    { title: t("campaigns.memberCol.takedown"), dataIndex: "takedown_state", render: (v: string | null) => (v ? t(`takedownState.${v}`, { defaultValue: v }) : "—") },
    {
      title: t("campaigns.memberCol.signals"),
      key: "signals",
      render: (_: unknown, m: Member) => (
        <Space direction="vertical" size={0}>
          {m.signals.map((s) => (
            <Typography.Text key={`${s.kind}-${s.value}-${s.with_finding}`} className="opti-mono">
              {t("campaigns.link", { other: valueOf.get(s.with_finding) ?? `#${s.with_finding}`, kind: t(`campaigns.signal.${s.kind}`), value: s.value })}
            </Typography.Text>
          ))}
        </Space>
      ),
    },
    { key: "actions", render: (_: unknown, m: Member) => actions(m) },
  ];

  const stateButtons = canTriage && (
    <Space>
      {c.state === "candidate" && (
        <>
          <Button type="primary" onClick={() => update.mutate({ state: "confirmed" }, { onError })}>{t("campaigns.confirm")}</Button>
          <Button onClick={() => update.mutate({ state: "dismissed" }, { onError })}>{t("campaigns.dismiss")}</Button>
        </>
      )}
      {c.state !== "candidate" && (
        <Popconfirm title={t("campaigns.reopenConfirm")} onConfirm={() => update.mutate({ state: "candidate" }, { onError })}>
          <Button>{t("campaigns.reopen")}</Button>
        </Popconfirm>
      )}
    </Space>
  );

  return (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Card
        title={
          <Space>
            <Button onClick={() => navigate("/campaigns")}>{t("common.back")}</Button>
            {campaignLabel(t, c)}
            <Tag>{t(`campaigns.state.${c.state}`)}</Tag>
          </Space>
        }
        extra={stateButtons}
      >
        <Typography.Paragraph type="secondary">{t("campaigns.review")}</Typography.Paragraph>
        <Descriptions
          column={{ xs: 1, md: 2 }}
          items={[
            { key: "members", label: t("campaigns.col.members"), children: c.member_count },
            { key: "active", label: t("campaigns.col.activeAlerts"), children: c.active_alerts },
            { key: "updated", label: t("campaigns.col.updatedAt"), children: fmtTime(c.updated_at) },
            ...(d.confirmed_by ? [{ key: "confirmed", label: t("campaigns.confirmedBy"), children: `${d.confirmed_by} · ${fmtTime(d.confirmed_at)}` }] : []),
          ]}
        />
        {d.ignored.length > 0 && (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 16 }}
            message={t("campaigns.ignored")}
            description={d.ignored.map((i) => (
              <div key={`${i.kind}-${i.value}`} className="opti-mono">
                {t("campaigns.ignoredItem", { kind: t(`campaigns.signal.${i.kind}`), value: i.value, count: i.count })}
              </div>
            ))}
          />
        )}
        {canTriage ? (
          <Form
            form={infoForm}
            name="campaign-info"
            layout="vertical"
            style={{ marginTop: 16 }}
            initialValues={{ name: c.name ?? "", note: d.note }}
            onFinish={(v) => update.mutate({ name: v.name, note: v.note }, { onSuccess: () => void message.success(t("campaigns.saved")), onError })}
          >
            <Form.Item name="name" label={t("campaigns.name")}><Input maxLength={200} placeholder={campaignLabel(t, { ...c, name: null })} /></Form.Item>
            <Form.Item name="note" label={t("campaigns.note")}><Input.TextArea maxLength={2000} rows={3} /></Form.Item>
            <Button htmlType="submit" loading={update.isPending}>{t("common.save")}</Button>
          </Form>
        ) : (
          d.note && <Typography.Paragraph style={{ marginTop: 16 }}>{d.note}</Typography.Paragraph>
        )}
      </Card>

      {confirmed && canTriage && (
        <Card title={t("campaigns.bulk.title")}>
          <Space direction="vertical">
            <Typography.Text type="secondary">{t("campaigns.bulk.noSuppress")}</Typography.Text>
            <Space wrap>
              <Button onClick={() => setBulkAction("verdict")}>{t("campaigns.bulk.verdict")}</Button>
              <Button onClick={() => setBulkAction("acknowledge")}>{t("campaigns.bulk.acknowledge")}</Button>
              <Button onClick={() => setBulkAction("close")}>{t("campaigns.bulk.close")}</Button>
            </Space>
          </Space>
        </Card>
      )}

      {confirmed && pending.length > 0 && (
        <Card title={t("campaigns.pending")} data-testid="campaign-pending">
          <Table<Member>
            rowKey="finding_id"
            size="middle"
            pagination={listPagination}
            dataSource={pending}
            columns={columns((m) =>
              canTriage ? (
                <Space>
                  <Button size="small" type="primary" onClick={() => decide.mutate({ findingId: m.finding_id, decision: "accept" }, { onError })}>{t("campaigns.accept")}</Button>
                  <Button size="small" onClick={() => decide.mutate({ findingId: m.finding_id, decision: "reject" }, { onError })}>{t("campaigns.reject")}</Button>
                </Space>
              ) : null,
            )}
          />
        </Card>
      )}

      <Card title={t("campaigns.members")}>
        <Table<Member>
          rowKey="finding_id"
          size="middle"
          pagination={listPagination}
          dataSource={c.state === "confirmed" ? members : d.members.filter((m) => m.state !== "excluded")}
          columns={columns((m) =>
            confirmed && canTriage ? (
              <Popconfirm title={t("campaigns.removeConfirm")} onConfirm={() => decide.mutate({ findingId: m.finding_id, decision: "remove" }, { onError })}>
                <Button size="small" danger>{t("campaigns.remove")}</Button>
              </Popconfirm>
            ) : null,
          )}
        />
      </Card>

      {excluded.length > 0 && (
        <Card title={t("campaigns.excluded")}>
          <Space wrap>
            {excluded.map((m) => <DomainText key={m.finding_id} value={m.value} />)}
          </Space>
        </Card>
      )}

      <Modal
        open={bulkAction !== null}
        title={bulkAction ? t(`campaigns.bulk.${bulkAction}`) : ""}
        okText={t("campaigns.bulk.run")}
        cancelText={t("common.cancel")}
        confirmLoading={bulk.isPending}
        onCancel={() => setBulkAction(null)}
        destroyOnHidden
        onOk={async () => {
          if (!bulkAction) return;
          let v: { verdict?: string; reason?: string } = {};
          if (bulkAction === "verdict") {
            try {
              v = await bulkForm.validateFields();
            } catch {
              return; // 表单已就地提示缺失项
            }
          }
          bulk.mutate(
            bulkAction === "verdict"
              ? { action: "verdict", verdict: v.verdict as (typeof VERDICTS)[number], reason: v.reason ?? "" }
              : { action: bulkAction, reason: "" },
            {
              onSuccess: (r) => {
                void message.success(t("campaigns.bulk.done", { updated: r.updated.length, skipped: r.skipped }));
                setBulkAction(null);
                bulkForm.resetFields();
              },
              onError,
            },
          );
        }}
      >
        <Typography.Paragraph>{t("campaigns.bulk.confirm", { count: affected })}</Typography.Paragraph>
        {bulkAction === "verdict" && (
          <Form form={bulkForm} name="campaign-bulk" layout="vertical">
            <Form.Item name="verdict" label={t("feedback.verdict")} rules={[{ required: true }]}>
              <Radio.Group options={VERDICTS.map((v) => ({ value: v, label: t(`verdict.${v}`) }))} />
            </Form.Item>
            <Form.Item name="reason" label={t("campaigns.bulk.reason")}><Input maxLength={2000} /></Form.Item>
          </Form>
        )}
      </Modal>
    </Space>
  );
}
