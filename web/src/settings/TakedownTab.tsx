import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Form, Input, InputNumber, Radio, Select, Space, Spin } from "antd";
import { useEffect, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useConfig, useMe } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import ConfigShell from "./ConfigShell";
import { useConfigSaver } from "./useConfigSaver";
import { useYamlMode } from "./useYamlMode";

type Json = Record<string, unknown>;
const SLA = ["registrar", "hosting", "cdn", "report", "platform"] as const;
const TAGS = { mode: "tags" as const, open: false, tokenSeparators: [",", " ", "\n"] };
const nonblank = (value: unknown) => typeof value === "string" && value.trim() ? value.trim() : null;

function cleanChannel(value: unknown): Json | null {
  if (!value || typeof value !== "object") return null;
  const channel = value as Json;
  const email = nonblank(channel.email), url = nonblank(channel.url);
  return email || url ? { email, url } : null;
}

const conv = {
  toForm: (data: Json) => data,
  fromForm: (value: Json): Json => ({
    ...value,
    providers: ((value.providers ?? []) as Json[]).map((row) => ({ ...row, channel: cleanChannel(row.channel) })),
    reporting: ((value.reporting ?? []) as Json[]).map((row) => ({ ...row, channel: cleanChannel(row.channel) })),
    platforms: ((value.platforms ?? []) as Json[]).map((row) => ({ ...row, channel: cleanChannel(row.channel) })),
    escalation: ((value.escalation ?? []) as Json[]).map((row) => ({ ...row, channel: cleanChannel(row.channel) })),
  }),
};

function Rows({ name, title, disabled, empty, fields }: {
  name: string; title: string; disabled: boolean; empty: Json; fields: (row: number) => ReactNode;
}) {
  const { t } = useTranslation();
  return <Card size="small" title={title}>
    <Form.List name={name}>{(rows, ops) => <Space direction="vertical" style={{ width: "100%" }}>
      {rows.map((row) => <Space key={row.key} wrap align="start" className="oti-config-term">
        {fields(row.name)}
        <Form.Item name={[row.name, "channel", "email"]} label={t("settings.takedown.email")}><Input style={{ width: 200 }} /></Form.Item>
        <Form.Item name={[row.name, "channel", "url"]} label={t("settings.takedown.url")}><Input style={{ width: 260 }} /></Form.Item>
        <Form.Item name={[row.name, "note"]} label={t("settings.takedown.note")}><Input style={{ width: 220 }} /></Form.Item>
        {!disabled && <Button type="text" icon={<MinusCircleOutlined />} aria-label={t("settings.takedown.remove")} onClick={() => ops.remove(row.name)} />}
      </Space>)}
      {!disabled && <Button size="small" icon={<PlusOutlined />} onClick={() => ops.add({ ...empty })}>{t("settings.takedown.add")}</Button>}
    </Space>}</Form.List>
  </Card>;
}

export default function TakedownTab() {
  const { t } = useTranslation();
  const me = useMe();
  const query = useConfig("takedown");
  const saver = useConfigSaver("takedown");
  const [form] = Form.useForm<Json>();
  const yaml = useYamlMode("takedown", form, conv);
  const canWrite = can(me.data, "config:write");
  useEffect(() => { if (query.data) yaml.load(query.data.data, query.data.yaml); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [query.data]);
  if (query.isPending) return <Spin />;
  if (query.isError) return <QueryError error={query.error} />;
  const config = query.data;
  const identity = (row: number) => <>
    <Form.Item name={[row, "id"]} label="ID" rules={[{ required: true, pattern: /^[a-z0-9_.-]{1,64}$/, message: t("settings.takedown.idRule") }]}><Input style={{ width: 140 }} /></Form.Item>
    <Form.Item name={[row, "name"]} label={t("settings.takedown.name")} rules={[{ required: true, message: t("settings.required") }]}><Input style={{ width: 180 }} /></Form.Item>
  </>;
  return <ConfigShell kind="takedown" config={config} canWrite={canWrite} saver={saver}
    onReload={() => { void query.refetch().then((result) => result.data && yaml.load(result.data.data, result.data.yaml)); }}
    onSave={async (note) => saver.submit({ ...(await yaml.body()), note, base_version: config.version })}>
    {yaml.errors.length > 0 && <Alert type="error" showIcon message={yaml.errors.map((e) => `${e.path} ${e.line ? `L${e.line} ` : ""}${e.message}`).join("；")} />}
    <Radio.Group optionType="button" value={yaml.mode} onChange={(event) => { void yaml.switchTo(event.target.value); }}
      options={[{ value: "form", label: t("settings.rules.modeForm") }, { value: "yaml", label: "YAML" }]} />
    {yaml.mode === "yaml" ? <Input.TextArea aria-label={t("settings.takedown.yaml")} className="opti-mono" rows={24}
      value={yaml.yamlText} readOnly={!canWrite} onChange={(event) => yaml.setYamlText(event.target.value)} /> :
      <Form form={form} layout="vertical" disabled={!canWrite} className="oti-config-form">
        <Card size="small" title={t("settings.takedown.sla")}><Space wrap>
          {SLA.map((kind) => <Form.Item key={kind} name={["sla_hours", kind]} label={t(`settings.takedown.slaKind.${kind}`)}><InputNumber min={0} max={8760} /></Form.Item>)}
          <Form.Item name="max_reminders" label={t("settings.takedown.maxReminders")}><InputNumber min={1} max={10} /></Form.Item>
        </Space></Card>
        <Rows name="providers" title={t("settings.takedown.providers")} disabled={!canWrite}
          empty={{ id: "", name: "", nameservers: [], network_names: [], orgs: [], channel: { email: null, url: null }, note: "" }}
          fields={(row) => <>{identity(row)}
            <Form.Item name={[row, "nameservers"]} label={t("settings.takedown.nameservers")}><Select {...TAGS} style={{ minWidth: 200 }} /></Form.Item>
            <Form.Item name={[row, "network_names"]} label={t("settings.takedown.networkNames")}><Select {...TAGS} style={{ minWidth: 180 }} /></Form.Item>
            <Form.Item name={[row, "orgs"]} label={t("settings.takedown.orgs")}><Select {...TAGS} style={{ minWidth: 160 }} /></Form.Item></>} />
        <Rows name="reporting" title={t("settings.takedown.reporting")} disabled={!canWrite}
          empty={{ id: "", name: "", tlds: [], channel: { email: null, url: null }, note: "" }}
          fields={(row) => <>{identity(row)}<Form.Item name={[row, "tlds"]} label={t("settings.takedown.tlds")} extra={t("settings.takedown.tldsHint")}><Select {...TAGS} style={{ minWidth: 160 }} /></Form.Item></>} />
        <Rows name="platforms" title={t("settings.takedown.platforms")} disabled={!canWrite}
          empty={{ id: "", name: "", hosts: [], channel: null, note: "" }}
          fields={(row) => <>{identity(row)}<Form.Item name={[row, "hosts"]} label={t("settings.takedown.hosts")} extra={t("settings.takedown.hostsHint")} rules={[{ required: true, message: t("settings.required") }]}><Select {...TAGS} style={{ minWidth: 220 }} /></Form.Item></>} />
        <Rows name="escalation" title={t("settings.takedown.escalation")} disabled={!canWrite}
          empty={{ kind: "registrar", name: "", channel: { email: null, url: null }, note: "" }}
          fields={(row) => <>
            <Form.Item name={[row, "kind"]} label={t("settings.takedown.kind")}><Select style={{ width: 140 }} options={SLA.map((kind) => ({ value: kind, label: t(`settings.takedown.slaKind.${kind}`) }))} /></Form.Item>
            <Form.Item name={[row, "name"]} label={t("settings.takedown.name")} rules={[{ required: true, message: t("settings.required") }]}><Input style={{ width: 180 }} /></Form.Item>
          </>} />
      </Form>}
  </ConfigShell>;
}
