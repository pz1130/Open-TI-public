import { useMutation, useQuery } from "@tanstack/react-query";
import { Alert, Button, Modal, Space, Table, Tag, Typography } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api, unwrap, type Schemas } from "../api/client";
import { usePagination } from "../components/pagination";
import QueryError from "../components/QueryError";
import { reloadProject } from "../shell/projectContext";

export default function ProjectsTab() {
  const { t } = useTranslation();
  const pagination = usePagination();
  const [target, setTarget] = useState<Schemas["ProjectSummary"] | null>(null);
  const q = useQuery({
    queryKey: ["projects", pagination.page, pagination.pageSize],
    queryFn: async () => unwrap(await api.GET("/api/v1/admin/projects", { params: { query: { page: pagination.page, page_size: pagination.pageSize } } })),
  });
  const activate = useMutation({
    retry: false,
    mutationFn: async () => unwrap(await api.POST("/api/v1/admin/projects/activate", { body: { project_id: target!.project_id, base_version: q.data!.rules_version } })),
    onSuccess: () => reloadProject(true),
  });
  return <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Typography.Title level={4}>{t("settings.tabs.projects")}</Typography.Title>
    <Alert type="warning" showIcon message={t("settings.projects.effect")} description={t("settings.projects.retained")} />
    {q.data && <Typography.Text>{t("settings.projects.current", { project: q.data.active_project })}</Typography.Text>}
    <Button onClick={() => void q.refetch()} loading={q.isFetching}>{t("common.refresh")}</Button>
    <QueryError error={q.error} />
    <Table<Schemas["ProjectSummary"]> rowKey="project_id" loading={q.isPending} dataSource={q.data?.items} scroll={{ x: 600 }} pagination={pagination.config(q.data?.total)} columns={[
      { title: t("settings.projects.name"), dataIndex: "name" },
      { title: t("settings.rules.project"), dataIndex: "project_id" },
      { title: t("settings.projects.status"), render: (_, item) => item.active ? <Tag color="success">{t("settings.projects.active")}</Tag> : !item.available ? <Tag color="warning">{t("settings.projects.unavailable")}</Tag> : <Tag>{t("settings.projects.ready")}</Tag> },
      { title: t("settings.projects.actions"), render: (_, item) => <Button disabled={item.active || !item.available || activate.isPending} onClick={() => { activate.reset(); setTarget(item); }}>{t("settings.projects.switch")}</Button> },
    ]} />
    <Typography.Paragraph type="secondary">{t("settings.projects.recovery")}</Typography.Paragraph>
    <Modal open={target !== null} title={t("settings.projects.confirm", { project: target?.project_id })} okText={t("settings.projects.switch")} cancelText={t("common.cancel")} confirmLoading={activate.isPending} closable={!activate.isPending} maskClosable={!activate.isPending} cancelButtonProps={{ disabled: activate.isPending }} onCancel={() => setTarget(null)} onOk={() => activate.mutate()}>
      <Typography.Paragraph>{t("settings.projects.effect")}</Typography.Paragraph>
      <Typography.Paragraph>{t("settings.projects.retained")}</Typography.Paragraph>
      {activate.error instanceof ApiError && activate.error.status === 409
        ? <Alert type="warning" message={t("settings.projects.conflict")} action={<Button onClick={() => { setTarget(null); activate.reset(); void q.refetch(); }}>{t("common.refresh")}</Button>} />
        : <QueryError error={activate.error} />}
    </Modal>
  </Space>;
}
