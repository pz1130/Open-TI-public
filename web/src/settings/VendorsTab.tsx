import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";
import { Alert, Button, Form, Input, Radio, Select, Space, Spin } from "antd";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useConfig, useMe } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import ConfigShell from "./ConfigShell";
import RematchStatus from "./RematchStatus";
import { useConfigSaver } from "./useConfigSaver";
import { useYamlMode } from "./useYamlMode";

type Json = Record<string, unknown>;
const TAGS = { mode: "tags" as const, open: false, tokenSeparators: [",", "\n"] };
const TIERS = ["critical", "high", "normal"];
const conv = { toForm: (data: Json) => data, fromForm: (value: Json) => value };

export default function VendorsTab() {
  const { t } = useTranslation();
  const me = useMe();
  const query = useConfig("vendors");
  const saver = useConfigSaver("vendors");
  const [form] = Form.useForm<Json>();
  const yaml = useYamlMode("vendors", form, conv);
  const canWrite = can(me.data, "config:write");
  useEffect(() => { if (query.data) yaml.load(query.data.data, query.data.yaml); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [query.data]);
  if (query.isPending) return <Spin />;
  if (query.isError) return <QueryError error={query.error} />;
  const config = query.data;
  return <ConfigShell kind="vendors" config={config} canWrite={canWrite} saver={saver}
    onReload={() => { void query.refetch().then((result) => result.data && yaml.load(result.data.data, result.data.yaml)); }}
    onSave={async (note) => saver.submit({ ...(await yaml.body()), note, base_version: config.version })}>
    <RematchStatus kind="vendors" />
    {yaml.errors.length > 0 && <Alert type="error" showIcon message={yaml.errors.map((error) => `${error.path} ${error.message}`).join("；")} />}
    <Radio.Group optionType="button" value={yaml.mode} onChange={(event) => { void yaml.switchTo(event.target.value); }}
      options={[{ value: "form", label: t("settings.rules.modeForm") }, { value: "yaml", label: "YAML" }]} />
    {yaml.mode === "yaml" ? <Input.TextArea aria-label={t("settings.inventory.yaml")} className="opti-mono" rows={20}
      value={yaml.yamlText} readOnly={!canWrite} onChange={(event) => yaml.setYamlText(event.target.value)} /> :
      <Form form={form} layout="vertical" disabled={!canWrite}>
        <Form.List name="vendors">{(rows, ops) => <Space direction="vertical" style={{ width: "100%" }}>
          {rows.map((row) => <Space key={row.key} wrap align="start" className="oti-config-term">
            <Form.Item name={[row.name, "id"]} label="ID" rules={[{ required: true, pattern: /^[a-z0-9][a-z0-9_.-]{0,63}$/, message: t("settings.takedown.idRule") }]}><Input style={{ width: 140 }} /></Form.Item>
            <Form.Item name={[row.name, "name"]} label={t("settings.takedown.name")} rules={[{ required: true, message: t("settings.required") }]}><Input style={{ width: 200 }} /></Form.Item>
            <Form.Item name={[row.name, "aliases"]} label={t("settings.inventory.aliases")}><Select {...TAGS} style={{ minWidth: 160 }} /></Form.Item>
            <Form.Item name={[row.name, "domains"]} label={t("settings.inventory.domains")}><Select {...TAGS} style={{ minWidth: 180 }} /></Form.Item>
            <Form.Item name={[row.name, "tier"]} label={t("settings.inventory.tier")}><Select style={{ width: 110 }} options={TIERS.map((value) => ({ value, label: t(`settings.inventory.tiers.${value}`) }))} /></Form.Item>
            <Form.Item name={[row.name, "owner"]} label={t("settings.inventory.owner")}><Input style={{ width: 140 }} /></Form.Item>
            {canWrite && <Button type="text" icon={<MinusCircleOutlined />} aria-label={t("settings.takedown.remove")} onClick={() => ops.remove(row.name)} />}
          </Space>)}
          {canWrite && <Button size="small" icon={<PlusOutlined />} aria-label={t("settings.takedown.add")}
            onClick={() => ops.add({ id: "", name: "", aliases: [], domains: [], tier: "normal", owner: "" })}>{t("settings.takedown.add")}</Button>}
        </Space>}</Form.List>
      </Form>}
  </ConfigShell>;
}
