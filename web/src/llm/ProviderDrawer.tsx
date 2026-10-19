import { App, AutoComplete, Button, Drawer, Form, Input, InputNumber, Select, Space, Switch, Typography } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage, type Schemas } from "../api/client";
import { useCreateLlmProvider, useLlmModels, useUpdateLlmProvider, type LlmPreset, type LlmProvider } from "../api/hooks";

interface Values {
  preset: string;
  name: string;
  base_url: string;
  model: string;
  api_key?: string;
  proxy?: string;
  json_mode: boolean;
  send_temperature: boolean;
  temperature: number;
  timeout_seconds: number;
}

const GROUPS = ["international", "domestic", "local"] as const;

export default function ProviderDrawer({ open, provider, presets, onClose }: {
  open: boolean;
  provider: LlmProvider | null; // null 表示新增
  presets: LlmPreset[];
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const [form] = Form.useForm<Values>();
  const [clearKey, setClearKey] = useState(false);
  const [clearProxy, setClearProxy] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const create = useCreateLlmProvider();
  const update = useUpdateLlmProvider();
  const fetchModels = useLlmModels();
  const sendTemperature = Form.useWatch("send_temperature", form);
  const presetKey = Form.useWatch("preset", form);
  const preset = presets.find((p) => p.key === (provider?.preset ?? presetKey));

  useEffect(() => {
    if (!open) return;
    setClearKey(false);
    setClearProxy(false);
    setModels([]);
    form.resetFields();
    if (provider) {
      form.setFieldsValue({
        preset: provider.preset, name: provider.name, base_url: provider.base_url, model: provider.model,
        json_mode: provider.json_mode, send_temperature: provider.temperature !== null,
        temperature: provider.temperature ?? 0, timeout_seconds: provider.timeout_seconds,
      });
    }
  }, [open, provider, form]);

  const applyPreset = (key: string) => {
    const p = presets.find((x) => x.key === key);
    if (!p) return;
    form.setFieldsValue({
      name: p.name, base_url: p.base_url, model: p.model, json_mode: p.json_mode,
      send_temperature: p.temperature !== null, temperature: p.temperature ?? 0,
    });
  };

  const onError = (e: unknown) => void message.error(t("common.error", { message: errorMessage(e) }));

  const submit = (v: Values) => {
    const temperature = v.send_temperature ? v.temperature : null;
    if (!provider) {
      const body: Schemas["LlmProviderIn"] = {
        name: v.name, preset: v.preset, base_url: v.base_url, model: v.model, json_mode: v.json_mode,
        temperature, timeout_seconds: v.timeout_seconds,
        ...(v.api_key ? { api_key: v.api_key } : {}),
        ...(v.proxy ? { proxy: v.proxy } : {}),
      };
      create.mutate(body, { onSuccess: () => { void message.success(t("llm.created")); onClose(); }, onError });
      return;
    }
    const body: Schemas["LlmProviderPatch"] = {
      name: v.name, base_url: v.base_url, model: v.model, json_mode: v.json_mode, temperature,
      timeout_seconds: v.timeout_seconds,
      ...(clearKey ? { api_key: null } : v.api_key ? { api_key: v.api_key } : {}),
      ...(clearProxy ? { proxy: null } : v.proxy ? { proxy: v.proxy } : {}),
    };
    update.mutate({ id: provider.id, body }, { onSuccess: () => { void message.success(t("llm.updated")); onClose(); }, onError });
  };

  const loadModels = () => {
    if (!provider) return;
    fetchModels.mutate(provider.id, {
      onSuccess: (r) => {
        setModels(r.models);
        void message.success(t("llm.modelsFetched", { n: r.models.length }));
      },
      onError,
    });
  };

  return (
    <Drawer open={open} width={520} title={t(provider ? "llm.drawerEdit" : "llm.drawerAdd")} onClose={onClose} destroyOnHidden>
      <Form<Values>
        form={form}
        name="llm-provider"
        layout="vertical"
        initialValues={{ json_mode: true, send_temperature: true, temperature: 0, timeout_seconds: 60 }}
        onFinish={submit}
      >
        {preset?.key === "minimax" && <Typography.Paragraph type="secondary">{t("llm.minimaxHint")}</Typography.Paragraph>}
        <Form.Item name="preset" label={t("llm.preset")} rules={[{ required: true }]}>
          <Select
            virtual={false}
            disabled={provider !== null}
            onChange={applyPreset}
            options={GROUPS.map((g) => ({
              label: t(`llm.group.${g}`),
              options: presets.filter((p) => p.group === g).map((p) => ({ value: p.key, label: p.name, title: p.name })),
            }))}
          />
        </Form.Item>
        <Form.Item name="name" label={t("llm.name")} rules={[{ required: true, max: 64 }]}><Input /></Form.Item>
        <Form.Item name="base_url" label={t("llm.baseUrl")} rules={[{ required: true, max: 512 }]}><Input className="opti-mono" /></Form.Item>
        <Form.Item label={t("llm.model")} required>
          <Space.Compact style={{ width: "100%" }}>
            <Form.Item name="model" noStyle rules={[{ required: true, max: 128 }]}>
              <AutoComplete aria-label={t("llm.model")} options={models.map((m) => ({ value: m }))} filterOption />
            </Form.Item>
            {provider && preset?.list_models !== "no" && (
              <Button onClick={loadModels} loading={fetchModels.isPending}>{t("llm.fetchModels")}</Button>
            )}
          </Space.Compact>
        </Form.Item>
        <Form.Item
          name="api_key"
          label={t("llm.apiKey")}
          extra={clearKey ? <Typography.Text type="warning">{t("llm.keyWillClear")}</Typography.Text> : undefined}
        >
          <Input.Password
            autoComplete="new-password"
            disabled={clearKey}
            placeholder={provider?.api_key_set ? t("llm.apiKeyPlaceholder", { hint: provider.api_key_hint ?? "" }) : undefined}
          />
        </Form.Item>
        {provider?.api_key_set && !clearKey && (
          <Button danger size="small" style={{ marginTop: -16, marginBottom: 16 }} onClick={() => setClearKey(true)}>{t("llm.clearKey")}</Button>
        )}
        <Form.Item name="proxy" label={t("llm.proxy")}>
          <Input
            className="opti-mono"
            disabled={clearProxy}
            placeholder={provider?.proxy_hint ? t("llm.proxyKept", { hint: provider.proxy_hint }) : t("llm.proxyPlaceholder")}
          />
        </Form.Item>
        {provider?.proxy_hint && !clearProxy && (
          <Button danger size="small" style={{ marginTop: -16, marginBottom: 16 }} onClick={() => setClearProxy(true)}>{t("llm.clearProxy")}</Button>
        )}
        <Space size="large" wrap>
          <Form.Item name="json_mode" hidden={preset?.protocol === "anthropic"} label={t("llm.jsonMode")} valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="send_temperature" label={t("llm.sendTemperature")} valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="temperature" label={t("llm.temperature")}>
            <InputNumber min={0} max={2} step={0.1} disabled={!sendTemperature} />
          </Form.Item>
          <Form.Item name="timeout_seconds" label={t("llm.timeout")} rules={[{ required: true }]}>
            <InputNumber min={1} max={300} />
          </Form.Item>
        </Space>
        <Button type="primary" htmlType="submit" loading={create.isPending || update.isPending}>{t("llm.saveProvider")}</Button>
      </Form>
    </Drawer>
  );
}
