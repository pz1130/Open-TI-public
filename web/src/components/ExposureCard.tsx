import { listPagination } from "./pagination";
import { Alert, Button, Card, Descriptions, Space, Spin, Table, Tag, Typography } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage } from "../api/client";
import { useExposure, useExposureAccounts, useMe, usePushExposure } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "./QueryError";
import { fmtTime } from "./format";

export default function ExposureCard({ alertId }: { alertId: number }) {
  const { t } = useTranslation();
  const me = useMe().data;
  const q = useExposure(alertId);
  const [show, setShow] = useState(false);
  const accounts = useExposureAccounts(alertId, show);
  const push = usePushExposure(alertId);
  if (q.isPending) return <Spin />;
  if (q.isError) return <QueryError error={q.error} />;
  const e = q.data;
  const stealer = e.kind === "stealer" || e.stealer_log;
  return (
    <Card title={t("exposure.title")}>
      <Space direction="vertical" style={{ width: "100%" }}>
        {push.isError && <Alert type="error" showIcon message={t("common.error", { message: errorMessage(push.error) })} />}
        {push.isSuccess && (
          <Alert type="success" showIcon message={t("exposure.pushed", { n: push.data.pushed, ref: push.data.ticket_ref ?? "-" })} />
        )}
        <Descriptions
          column={{ xs: 1, md: 2 }}
          items={[
            { key: "event", label: t("exposure.event"), children: e.title },
            { key: "source", label: t("exposure.source"), children: t(`exposure.sources.${e.source}`, { defaultValue: e.source }) },
            { key: "date", label: stealer ? t("exposure.lastInfection") : t("exposure.breachDate"), children: e.breach_date ?? "-" },
            { key: "affected", label: t("exposure.affected"), children: e.affected },
            { key: "pending", label: t("exposure.pending"), children: `${e.accounts_pending} / ${e.accounts_total}` },
            {
              key: "classes",
              label: t("exposure.dataClasses"),
              children: (
                <Space wrap>
                  {e.data_classes.map((c) => (
                    <Tag key={c} color={c === "Passwords" ? "red" : undefined}>
                      {c}
                    </Tag>
                  ))}
                </Space>
              ),
            },
            {
              key: "flags",
              label: t("exposure.flags"),
              children: (
                <Space wrap>
                  {stealer && <Tag color="volcano">{t("exposure.stealer")}</Tag>}
                  {!e.verified && <Tag>{t("exposure.unverified")}</Tag>}
                  {e.fabricated && <Tag>{t("exposure.fabricated")}</Tag>}
                  {e.spam_list && <Tag>{t("exposure.spamList")}</Tag>}
                  {e.sensitive && <Tag color="purple">{t("exposure.sensitive")}</Tag>}
                </Space>
              ),
            },
          ]}
        />
        <Typography.Text type="secondary">{t("exposure.policy")}</Typography.Text>
        <Space wrap>
          {can(me, "tickets:push") && e.can_push && e.accounts_pending > 0 && (
            <Button type="primary" loading={push.isPending} onClick={() => push.mutate()}>
              {t("exposure.push", { n: e.accounts_pending })}
            </Button>
          )}
          {can(me, "exposure:accounts") && e.accounts_total > 0 && !show && (
            <Button onClick={() => setShow(true)}>{t("exposure.showAccounts")}</Button>
          )}
        </Space>
        {show &&
          (accounts.isPending ? (
            <Spin />
          ) : accounts.isError ? (
            <QueryError error={accounts.error} />
          ) : (
            <Table
              rowKey="email"
              size="small"
              pagination={listPagination}
              dataSource={accounts.data}
              columns={[
                { title: t("exposure.email"), dataIndex: "email" },
                { title: t("exposure.firstSeen"), dataIndex: "first_seen", render: (v: string) => fmtTime(v) },
                {
                  title: t("exposure.pushedAt"),
                  dataIndex: "pushed_at",
                  render: (v: string | null) => (v ? fmtTime(v) : t("exposure.notPushed")),
                },
              ]}
            />
          ))}
      </Space>
    </Card>
  );
}
