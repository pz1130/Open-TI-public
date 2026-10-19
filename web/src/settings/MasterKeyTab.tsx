import { Alert, App, Button, Card, Input, Space, Spin, Tag, Typography } from "antd";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, errorMessage, unwrap } from "../api/client";
import { Link } from "react-router";
import QueryError from "../components/QueryError";

export default function MasterKeyTab() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const cache = useQueryClient();
  const [importKey, setImportKey] = useState("");
  const [backup, setBackup] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const q = useQuery({ queryKey: ["master-key"], queryFn: async () => unwrap(await api.GET("/api/v1/admin/master-key")) });

  async function initialize(imported: boolean) {
    setPending(true);
    setError("");
    try {
      // 主密钥只留在当前组件中，不放进查询/变更缓存或浏览器存储。
      const result = unwrap(await api.POST("/api/v1/admin/master-key", { body: imported ? { key: importKey.trim() } : {} }));
      setBackup(result.backup_key ?? null);
      setImportKey("");
      await cache.invalidateQueries();
      message.success(t("settings.masterKey.saved"));
    } catch (e) { setError(errorMessage(e)); }
    finally { setPending(false); }
  }

  if (q.isPending) return <Spin />;
  if (q.isError) return <QueryError error={q.error} />;
  return <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Typography.Title level={4}>{t("settings.tabs.master_key")}</Typography.Title>
    <Typography.Paragraph>{t("settings.masterKey.description")}</Typography.Paragraph>
    <Tag color={q.data.configured ? "success" : "warning"}>{q.data.configured ? t("settings.masterKey.configured", { source: t(`settings.masterKey.source.${q.data.source}`) }) : t("settings.masterKey.missing")}</Tag>
    {error && <Alert type="error" message={error} showIcon />}
    {backup && <Alert type="warning" showIcon message={t("settings.masterKey.backupTitle")} description={<Space direction="vertical">
      <Typography.Paragraph>{t("settings.masterKey.backupHint")}</Typography.Paragraph>
      <Typography.Text code copyable>{backup}</Typography.Text>
      <Button onClick={() => setBackup(null)}>{t("settings.masterKey.backedUp")}</Button>
    </Space>} />}
    {!q.data.configured && <Card>
      {q.data.has_encrypted_credentials ? <Alert type="warning" showIcon message={t("settings.masterKey.restoreRequired")} /> : <>
        <Typography.Paragraph>{t("settings.masterKey.generateHint")}</Typography.Paragraph>
        <Button type="primary" loading={pending} onClick={() => void initialize(false)}>{t("settings.masterKey.generate")}</Button>
      </>}
      <Typography.Title level={5}>{t("settings.masterKey.importTitle")}</Typography.Title>
      <form onSubmit={(e) => { e.preventDefault(); if (importKey.trim() && !pending) void initialize(true); }}>
        <Space.Compact style={{ width: "100%" }}>
          <Input.Password value={importKey} onChange={(e) => setImportKey(e.target.value)} aria-label={t("settings.masterKey.importTitle")} autoComplete="new-password" />
          <Button loading={pending} disabled={!importKey.trim()} htmlType="submit">{t("settings.masterKey.import")}</Button>
        </Space.Compact>
      </form>
    </Card>}
    <Typography.Paragraph type="secondary">{t("settings.masterKey.persistence")}</Typography.Paragraph>
    <Link to="/settings/services">{t("settings.tabs.services")}</Link>
  </Space>;
}
