import { listPagination } from "../components/pagination";
import { Alert, App, Button, Card, Form, Input, InputNumber, Popconfirm, Select, Slider, Space, Switch, Table, Tag, Tooltip, Typography, type TableProps } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorMessage } from "../api/client";
import {
  useDeleteLlmProvider, useLlmPresets, useLlmProviders, useLlmSettings, useLlmStatus, useMe,
  useSaveLlmSettings, useTestLlmProvider, type LlmProvider,
} from "../api/hooks";
import { can } from "../auth/perms";
import { fmtTime } from "../components/format";
import QueryError from "../components/QueryError";
import ProviderDrawer from "../llm/ProviderDrawer";

interface SettingsValues {
  enabled: boolean;
  primary_id: number | null;
  backup_id: number | null;
  gray_zone: [number, number];
  max_per_run: number;
  max_attempts: number;
  max_wait_minutes: number;
  summary_language: string;
  code_enabled: boolean;
}

const GROUP_COLOR: Record<string, string> = { international: "orange", domestic: "blue", local: "green" };

export default function LlmPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const writable = can(useMe().data, "llm:admin");
  const presets = useLlmPresets();
  const providers = useLlmProviders();
  const settings = useLlmSettings();
  const status = useLlmStatus();
  const save = useSaveLlmSettings();
  const remove = useDeleteLlmProvider();
  const test = useTestLlmProvider();
  const [form] = Form.useForm<SettingsValues>();
  const [editing, setEditing] = useState<LlmProvider | null | undefined>(undefined); // undefined：抽屉关闭
  const onError = (e: unknown) => void message.error(t("common.error", { message: errorMessage(e) }));

  useEffect(() => {
    const s = settings.data;
    if (!s) return;
    form.setFieldsValue({ ...s, gray_zone: [s.gray_zone_low, s.gray_zone_high] });
  }, [settings.data, form]);

  const list = providers.data ?? [];
  const primary = Form.useWatch("primary_id", form);
  const backup = Form.useWatch("backup_id", form);
  const overseas = list.some((p) => (p.id === primary || p.id === backup) && p.group === "international");
  const usable = list.filter((p) => p.api_key_set || !(presets.data ?? []).find((x) => x.key === p.preset)?.key_required);
  const options = usable.map((p) => ({ value: p.id, label: `${p.name} · ${p.model}` }));

  const submit = (v: SettingsValues) =>
    save.mutate(
      {
        enabled: v.enabled, primary_id: v.primary_id ?? null, backup_id: v.backup_id ?? null,
        gray_zone_low: v.gray_zone[0], gray_zone_high: v.gray_zone[1], max_per_run: v.max_per_run,
        max_attempts: v.max_attempts, max_wait_minutes: v.max_wait_minutes, summary_language: v.summary_language,
        code_enabled: v.code_enabled ?? false,
      },
      { onSuccess: () => void message.success(t("llm.saved")), onError },
    );

  const runTest = (p: LlmProvider) =>
    test.mutate(p.id, {
      onSuccess: (r) =>
        r.ok
          ? void message.success(t("llm.testOk", { verdict: t(`llm.verdict.${r.verdict}`, { defaultValue: r.verdict ?? "" }), ms: r.latency_ms }))
          : void message.error(t("llm.testFail", { error: r.error })),
      onError,
    });

  const columns: TableProps<LlmProvider>["columns"] = [
    {
      title: t("llm.name"),
      dataIndex: "name",
      render: (v: string, r) => (
        <Space>
          {v}
          {r.in_use && <Tag color="purple">{t(`llm.inUse.${r.in_use}`)}</Tag>}
        </Space>
      ),
    },
    {
      title: t("llm.preset"),
      dataIndex: "preset",
      render: (v: string, r) => (
        <Space>
          {(presets.data ?? []).find((p) => p.key === v)?.name ?? v}
          <Tag color={GROUP_COLOR[r.group]}>{t(`llm.group.${r.group}`, { defaultValue: r.group })}</Tag>
        </Space>
      ),
    },
    { title: t("llm.model"), dataIndex: "model", render: (v: string) => <span className="opti-mono">{v}</span> },
    {
      title: t("llm.key"),
      key: "key",
      render: (_: unknown, r) => (r.api_key_set ? t("llm.keySet", { hint: r.api_key_hint ?? "" }) : <Typography.Text type="secondary">{t("llm.keyUnset")}</Typography.Text>),
    },
    { title: t("llm.proxy"), dataIndex: "proxy_hint", render: (v: string | null) => (v ? <span className="opti-mono">{v}</span> : "—") },
    {
      title: t("llm.lastTest"),
      key: "test",
      render: (_: unknown, r) =>
        r.last_test_at === null ? (
          <Typography.Text type="secondary">{t("llm.never")}</Typography.Text>
        ) : (
          <Tooltip title={r.last_test_error ?? undefined}>
            <Space>
              <Tag color={r.last_test_ok ? "green" : "red"}>{t(r.last_test_ok ? "llm.ok" : "llm.failed")}</Tag>
              {fmtTime(r.last_test_at)}
            </Space>
          </Tooltip>
        ),
    },
    {
      key: "actions",
      render: (_: unknown, r) =>
        writable ? (
          <Space>
            <Button size="small" aria-label={t("llm.testLabel", { name: r.name })} loading={test.isPending && test.variables === r.id} onClick={() => runTest(r)}>
              {t("llm.test")}
            </Button>
            <Button size="small" aria-label={t("llm.editLabel", { name: r.name })} onClick={() => setEditing(r)}>{t("llm.edit")}</Button>
            <Tooltip title={r.in_use ? t("llm.inUseNoDelete") : undefined}>
              <Popconfirm
                title={t("llm.deleteConfirm")}
                disabled={r.in_use !== null}
                onConfirm={() => remove.mutate(r.id, { onSuccess: () => void message.success(t("llm.deleted")), onError })}
              >
                <Button size="small" danger disabled={r.in_use !== null} aria-label={t("llm.deleteLabel", { name: r.name })}>{t("llm.delete")}</Button>
              </Popconfirm>
            </Tooltip>
          </Space>
        ) : null,
    },
  ];

  return (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      {status.data && !status.data.encryption_key && <Alert type="error" showIcon message={t("llm.noKeyAlert")} description={writable && <Link to="/settings/master_key">{t("settings.masterKey.open")}</Link>} />}
      {status.data?.problem && <Alert type="warning" showIcon message={status.data.problem} />}
      {status.data?.worker_problem && status.data.worker_problem !== status.data.problem && (
        <Alert type="warning" showIcon message={t("llm.workerProblem", { problem: status.data.worker_problem })} />
      )}
      {overseas && <Alert type="info" showIcon message={t("llm.overseasAlert")} />}
      <Card
        title={t("llm.settings")}
        extra={status.data && (
          <Space split="·">
            <span>{t("llm.queue", { n: status.data.queue })}</span>
            <span>{t("llm.last24h", { done: status.data.done_24h, failed: status.data.failed_24h })}</span>
            {status.data.worker_checked_at && <span>{t("llm.workerChecked", { time: fmtTime(status.data.worker_checked_at) })}</span>}
          </Space>
        )}
      >
        <QueryError error={settings.error ?? status.error} />
        <Form<SettingsValues> form={form} name="llm-settings" layout="vertical" disabled={!writable} onFinish={submit}>
          <Form.Item name="enabled" label={t("llm.enabled")} valuePropName="checked"><Switch /></Form.Item>
          <Space size="large" wrap>
            <Form.Item
              name="primary_id"
              label={t("llm.primary")}
              style={{ minWidth: 260 }}
              dependencies={["enabled"]}
              rules={[({ getFieldValue }) => ({
                validator: (_, v) =>
                  getFieldValue("enabled") && v == null ? Promise.reject(new Error(t("llm.needPrimary"))) : Promise.resolve(),
              })]}
            >
              <Select allowClear options={options} />
            </Form.Item>
            <Form.Item
              name="backup_id"
              label={t("llm.backup")}
              style={{ minWidth: 260 }}
              dependencies={["primary_id"]}
              rules={[({ getFieldValue }) => ({
                validator: (_, v) =>
                  v != null && getFieldValue("primary_id") == null
                    ? Promise.reject(new Error(t("llm.backupNeedsPrimary")))
                    : Promise.resolve(),
              })]}
            >
              <Select allowClear options={options.filter((o) => o.value !== primary)} />
            </Form.Item>
          </Space>
          <Form.Item name="gray_zone" label={t("llm.grayZone")} style={{ maxWidth: 420 }}>
            <Slider range min={0} max={100} />
          </Form.Item>
          <Form.Item name="code_enabled" label={t("llm.codeEnabled")} valuePropName="checked" extra={t("llm.codeEnabledHelp")}>
            <Switch />
          </Form.Item>
          <Space size="large" wrap>
            <Form.Item name="max_per_run" label={t("llm.maxPerRun")}><InputNumber min={1} max={200} /></Form.Item>
            <Form.Item name="max_attempts" label={t("llm.maxAttempts")}><InputNumber min={1} max={10} /></Form.Item>
            <Form.Item name="max_wait_minutes" label={t("llm.maxWait")}><InputNumber min={1} max={1440} /></Form.Item>
            <Form.Item name="summary_language" label={t("llm.summaryLanguage")} rules={[{ required: true, max: 32 }]}><Input /></Form.Item>
          </Space>
          {writable && <Button type="primary" htmlType="submit" loading={save.isPending}>{t("common.save")}</Button>}
        </Form>
      </Card>
      <Card
        title={t("llm.providers")}
        extra={writable && <Button type="primary" onClick={() => setEditing(null)}>{t("llm.add")}</Button>}
      >
        <QueryError error={providers.error} />
        <Table<LlmProvider> rowKey="id" size="middle" loading={providers.isPending} dataSource={list} columns={columns} pagination={listPagination} scroll={{ x: true }} />
      </Card>
      <ProviderDrawer open={editing !== undefined} provider={editing ?? null} presets={presets.data ?? []} onClose={() => setEditing(undefined)} />
    </Space>
  );
}
