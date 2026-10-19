import { Alert, App, Button, Card, Checkbox, Descriptions, Popconfirm, Space, Spin, Tag, Typography } from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, errorMessage, unwrap, type Schemas } from "../api/client";
import QueryError from "../components/QueryError";
import { fmtTime } from "../components/format";

type Service = Schemas["RestartRequest"]["services"][number];
const key = ["service-control"];
const active = (phase?: string) => phase === "queued" || phase === "running";

export default function ServicesTab() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const cache = useQueryClient();
  const [services, setServices] = useState<Service[]>(["api", "worker"]);
  const q = useQuery({
    queryKey: key,
    queryFn: async () => unwrap(await api.GET("/api/v1/admin/services")),
    refetchInterval: 2000,
  });
  const restart = useMutation({
    retry: false, // A dropped response must never issue a second restart automatically.
    mutationFn: async () => unwrap(await api.POST("/api/v1/admin/services/restart", { body: { services, reason: "" } })),
    onSuccess: (operation) => {
      cache.setQueryData<Schemas["ServiceStatus"]>(key, (previous) => previous ? { ...previous, operation } : previous);
      void cache.invalidateQueries({ queryKey: key });
      void message.success(t("settings.services.accepted"));
    },
    onError: () => void cache.invalidateQueries({ queryKey: key }),
  });
  if (q.isPending) return <Spin />;
  const job = q.data?.operation;
  const busy = active(job?.phase);
  const reconnecting = busy && job?.services.includes("api");
  return <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Typography.Title level={4}>{t("settings.tabs.services")}</Typography.Title>
    <Typography.Paragraph>{t("settings.services.description")}</Typography.Paragraph>
    <Typography.Paragraph type="secondary">{t("settings.services.effect")}</Typography.Paragraph>
    {q.error && (reconnecting
      ? <Alert type="info" showIcon message={t("settings.services.reconnecting")} />
      : <QueryError error={q.error} />)}
    {q.data && !q.data.available && <Alert type="warning" showIcon message={t(`settings.services.problems.${q.data.problem ?? "offline"}`)} />}
    <Card title={t("settings.services.status")} extra={<Button onClick={() => void q.refetch()} loading={q.isFetching}>{t("common.refresh")}</Button>}>
      <Descriptions column={1} items={(q.data?.services ?? []).map((service) => ({
        key: service.name,
        label: t(`settings.services.names.${service.name}`),
        children: <Tag color={service.running === service.containers && service.running > 0 ? "success" : "warning"}>{t("settings.services.running", { running: service.running, total: service.containers })}</Tag>,
      }))} />
      <Checkbox.Group value={services} onChange={(values) => setServices(values as Service[])} options={["api", "worker"].map((value) => ({ value, label: t(`settings.services.names.${value}`) }))} />
      <div style={{ marginTop: 16 }}>
        <Popconfirm title={t("settings.services.confirm")} description={t("settings.services.effect")} onConfirm={() => restart.mutate()} disabled={busy || !q.data?.available || !services.length}>
          <Button danger type="primary" disabled={busy || !q.data?.available || !services.length} loading={restart.isPending}>{t("settings.services.restart")}</Button>
        </Popconfirm>
      </div>
      {restart.error && <Alert style={{ marginTop: 16 }} showIcon type="error" message={errorMessage(restart.error)} description={t("settings.services.checkStatus")} />}
    </Card>
    {job && <Card title={t("settings.services.lastOperation")}>
      <Space direction="vertical">
        <Tag color={job.phase === "failed" ? "error" : job.phase === "completed" ? "success" : "processing"}>{t(`settings.services.phases.${job.phase}`)}</Tag>
        <Typography.Text>{job.services.map((service) => t(`settings.services.names.${service}`)).join(" · ")}</Typography.Text>
        <Typography.Text type="secondary">{fmtTime(job.updated_at)}</Typography.Text>
        {(job.completed_services ?? []).length > 0 && <Typography.Text>{t("settings.services.finished", { services: (job.completed_services ?? []).map((service) => t(`settings.services.names.${service}`)).join(" · ") })}</Typography.Text>}
        {job.error && <Alert type="error" showIcon message={t(`settings.services.errors.${job.error}`, { defaultValue: t("settings.services.errors.restart_failed") })} />}
      </Space>
    </Card>}
  </Space>;
}
