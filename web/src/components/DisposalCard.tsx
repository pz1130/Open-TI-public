import { Alert, Button, Card, Descriptions, Input, Modal, Radio, Space, Spin, Tag, Typography } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import { errorMessage, type Schemas } from "../api/client";
import { evidenceBundleUrl, useCreateTakedown, useMe, usePushTicket, useSetTicketRef, useTakedownTargets } from "../api/hooks";
import { can } from "../auth/perms";
import { TakedownStateTag } from "./tags";

type Language = Schemas["TakedownIn"]["language"];

function TargetPicker({ alertId, onCreated }: { alertId: number; onCreated: (id: number) => void }) {
  const { t } = useTranslation();
  const [targetId, setTargetId] = useState<string>();
  const [language, setLanguage] = useState<Language>("zh-CN");
  const targets = useTakedownTargets(alertId, true);
  const create = useCreateTakedown(alertId);
  return (
    <Modal
      open
      title={t("disposal.newTakedown")}
      okText={t("disposal.createDraft")}
      okButtonProps={{ disabled: !targetId, loading: create.isPending }}
      onCancel={() => onCreated(0)}
      onOk={() => targetId && create.mutate({ target_id: targetId, language }, { onSuccess: (td) => onCreated(td.id) })}
    >
      {create.isError && <Alert type="error" showIcon message={t("common.error", { message: errorMessage(create.error) })} />}
      {targets.isPending ? (
        <Spin />
      ) : targets.isError ? (
        <Alert type="error" showIcon message={t("common.error", { message: errorMessage(targets.error) })} />
      ) : (
        <Space direction="vertical" style={{ width: "100%" }}>
          {targets.data.missing_hosting.length > 0 && (
            <Alert type="info" showIcon message={t("disposal.hostingPending", { ips: targets.data.missing_hosting.join(", ") })} />
          )}
          <Radio.Group
            value={language}
            optionType="button"
            onChange={(e) => setLanguage(e.target.value as Language)}
            options={[{ label: "中文", value: "zh-CN" }, { label: "English", value: "en-US" }]}
          />
          <Radio.Group value={targetId} onChange={(e) => setTargetId(e.target.value as string)}>
            <Space direction="vertical">
              {targets.data.targets.map((tg) => (
                <Radio key={tg.id} value={tg.id}>
                  <Space wrap>
                    <Tag>{t(`targetKind.${tg.kind}`, { defaultValue: tg.kind })}</Tag>
                    <strong>{tg.name}</strong>
                    <Typography.Text type="secondary">{tg.email ?? tg.url ?? t("disposal.noContact")}</Typography.Text>
                    <Typography.Text type="secondary">
                      {t(`basis.${tg.basis}`, { defaultValue: tg.basis })}
                      {tg.detail ? ` · ${tg.detail}` : ""}
                    </Typography.Text>
                  </Space>
                  {tg.note && (
                    <div>
                      <Typography.Text type="warning">{tg.note}</Typography.Text>
                    </div>
                  )}
                </Radio>
              ))}
            </Space>
          </Radio.Group>
        </Space>
      )}
    </Modal>
  );
}

export default function DisposalCard({ detail }: { detail: Schemas["AlertDetail"] }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const me = useMe().data;
  const alertId = detail.alert.id;
  const push = usePushTicket(alertId);
  const setRef = useSetTicketRef(alertId);
  const [ref, setRefText] = useState("");
  const [picking, setPicking] = useState(false);
  const ticket = detail.ticket;
  const canPush = can(me, "tickets:push");
  const error = push.error ?? setRef.error;
  return (
    <Card
      title={t("disposal.title")}
      extra={can(me, "evidence:export") && <Button href={evidenceBundleUrl(alertId)}>{t("disposal.bundle")}</Button>}
    >
      {error && <Alert type="error" showIcon message={t("common.error", { message: errorMessage(error) })} style={{ marginBottom: 16 }} />}
      <Descriptions
        column={1}
        items={[
          {
            key: "ticket",
            label: t("disposal.ticket"),
            children: (
              <Space wrap>
                {ticket.ref && ticket.url ? (
                  <Typography.Link className="opti-mono" href={ticket.url} target="_blank" rel="noreferrer">{ticket.ref}</Typography.Link>
                ) : ticket.ref ? (
                  <Typography.Text className="opti-mono">{ticket.ref}</Typography.Text>
                ) : (
                  <span>{ticket.pushed_at ? t("disposal.ticketPending") : t("disposal.ticketNone")}</span>
                )}
                {ticket.status && <Tag>{ticket.status}</Tag>}
                {canPush && detail.finding.category !== "credential_exposure" && ticket.available && !ticket.pushed_at && (
                  <Button loading={push.isPending} onClick={() => push.mutate()}>
                    {t("disposal.push")}
                  </Button>
                )}
                {canPush && !ticket.ref && (
                  <Space.Compact>
                    <Input
                      aria-label={t("disposal.ticketRef")}
                      placeholder={t("disposal.ticketRef")}
                      value={ref}
                      onChange={(e) => setRefText(e.target.value)}
                    />
                    <Button disabled={!ref.trim()} onClick={() => setRef.mutate({ ticket_ref: ref.trim() })}>
                      {t("disposal.saveRef")}
                    </Button>
                  </Space.Compact>
                )}
              </Space>
            ),
          },
          {
            key: "takedowns",
            label: t("disposal.takedowns"),
            children: (
              <Space direction="vertical">
                {detail.takedowns.length === 0 && <span>{t("disposal.noTakedowns")}</span>}
                {detail.takedowns.map((td) => (
                  <Space key={td.id}>
                    <Link to={`/takedowns?id=${td.id}`}>#{td.id}</Link>
                    <TakedownStateTag value={td.state} />
                    <span>{td.target_name}</span>
                  </Space>
                ))}
                {can(me, "takedown:draft") && (
                  <Button type="primary" onClick={() => setPicking(true)}>
                    {t("disposal.newTakedown")}
                  </Button>
                )}
              </Space>
            ),
          },
        ]}
      />
      {picking && (
        <TargetPicker
          alertId={alertId}
          onCreated={(id) => {
            setPicking(false);
            if (id) navigate(`/takedowns?id=${id}`);
          }}
        />
      )}
    </Card>
  );
}
